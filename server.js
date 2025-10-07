const express = require('express');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const ejs = require('ejs');
const  bodyParser = require('body-parser');
const session = require('express-session');
const mongooseSession = require('connect-mongodb-session')(session);
// const model= require('./backend/models/Issue'); // Import the Issue model
const Issue = require('./backend/models/Issue');
const Signin = require('./backend/models/User');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const cookieParser = require('cookie-parser');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const nodemailer = require('nodemailer');
const otps = {}; // In-memory store for OTPs
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
app.use(cookieParser());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'undoBharat_issues',
    allowed_formats: ['jpg', 'jpeg', 'png'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }]
  }
});

const upload = multer({ storage: storage });


 
// Load environment variables from .env


const port = 5000; // Make sure this matches the port used in your HTML form fetch()
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.json());
// storing data in session
const store = new mongooseSession({
    uri: process.env.MONGODB_URI,
    collection: 'mysessions',
    // give a name to seesion

});

app.use(session({
  secret: 'undoBharat_secret_key', // change this to a strong secret
  resave: false,
  saveUninitialized: false,
  store: store, // Use MongoDB session store
  cookie: {
    secure: false, // set true only in production with HTTPS
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));
 
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'frontend', 'views'));
// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => console.error('❌ Error connecting to MongoDB:', err));

 // Import the login model


const signin = async (req, res) => {
  try {
    const { fullname, email, password, role, adminCode } = req.body;

    const existingUser = await Signin.findOne({ email });
    if (existingUser) {
      return res.redirect('/api/signin-login?msg=User already exists. Please log in.');
    }

    // Admin code check
    if (role === 'admin') {
      if (!adminCode || adminCode !== process.env.ADMIN_CODE) {
        return res.redirect('/signin?msg=Invalid admin code. Please try again.');
      }
    }
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
    const newUser = new Signin({
      fullname,
      email,
      password: hashedPassword, // Store hashed password
      role
    });

    await newUser.save();
    req.session.userName = newUser.fullname;

    // If admin, log in and redirect to admin page
    if (role === 'admin') {
      req.session.user = { id: newUser._id, fullname: newUser.fullname, role: newUser.role, isAuthenticated: true };
      req.session.IsAuthenticated = true;
      res.cookie('userRole', newUser.role, { maxAge: 3600000, httpOnly: true });
      res.cookie('userEmail', newUser.email, { maxAge: 3600000 });
      return res.redirect('/api/admins');
    }

    return res.redirect('/api/signin-login?success=true');
  } catch (error) {
    console.error('Error creating user:', error);
    if (!res.headersSent) {
      return res.status(500).json({ error: 'Failed to create user' });
    }
  }
};
// ✅ Login function
// This function handles user login, checks credentials, and sets session data
const login = async (req, res) => {
 const { email, password} = req.body;

  try {
    const user = await Signin.findOne({ email });

    if (!user) {
      return res.render('login', { message: 'User not found, Please signin' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password); // Compare hashed password
    if (!isPasswordValid) {
      return res.render('login', { message: 'Invalid credentials' });
    }

      
      res.cookie('userRole', user.role, { maxAge: 3600000, httpOnly: true });
      res.cookie('userEmail', user.email, { maxAge: 3600000 });
     
      
     // ✅ Set session
    req.session.user = {
      id: user._id,
      fullname: user.fullname,
      email: user.email,
      role: user.role,
      isAuthenticated: true
    };
    req.session.IsAuthenticated = true; // Set authentication status

    const token = jwt.sign(
        { id: user._id, fullname: user.fullname, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // 1 hour

   
    // ✅ Redirect based on role 
    if (user.role === 'admin') {
      return res.redirect('/api/admin');
    } else {
      return res.redirect('/api/report-an-issue-now');
    }

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send('Internal Server Error');
  }
}

     const authenticateJWT =(req, res, next)=>{
        const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
        if (!token) return res.redirect('/login');
        jwt.verify(token, JWT_SECRET, (err, user) => {
          if (err) return res.redirect('/login');
          req.jwtUser = user;
          next();
        });
      }
// cheking if user is logged in or not
// This middleware checks if the user is authenticated before accessing certain routes
const login_or_not=(req,res,next)=>{
  if(req.session.IsAuthenticated){
    next()
  }
  else{
    res.redirect('/signin'); // Redirect to signup if not authenticated
  }
}
// app.use('/api/user', userRoutes);
// app.use('/api/admin', adminRoutes);

// ✅ Root user route
app.get('/api/report-an-issue-now', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'user') {
    console.log(req.session.user.role);
    return res.redirect('/');
  }
  const deletedMsg = req.query.deleted === 'true' ? 'Your issue was deleted by admin.' : null;
  res.render('report_issue', { user: req.session.user, deletedMsg });
});

app.get('/api/admins', async(req, res) => {
res.render('login', { message: 'You are not authorized to access this page. Please log in as an admin.' });
});

// admin admin route 
app.get('/api/admin', authenticateJWT,async(req, res) => {
  if (!req.jwtUser || req.jwtUser.role !== 'admin') {
        return res.redirect('/?notAdmin=true');
  }
  try {
    const issues = await Issue.find().sort({ createdAt: -1 });
    const Adminname = req.jwtUser.fullname; // Get admin name from session
    const Adminmail = req.jwtUser.email; // Get admin email from session
    res.render('admin', { user:  req.jwtUser, issues, msg: req.query.msg,Adminname,Adminmail}); // ✅ issues passed here
  } catch (err) {
    console.error("Error loading admin dashboard:", err);
    res.status(500).send("Server error");
  }
});
// reporitng new issue
app.post('/api/report-new-issue', login_or_not, upload.array('images'), async (req, res) => {
  try {
    const { name, mobile, title, description, problemType, address, pincode, date } = req.body;
    const imageUrls = req.files.map(file => file.path); // Cloudinary URL
    const newIssue = new Issue({
      name,
      mobile,
      title,
      description,
      images: imageUrls, // Store array of image URLs
      problemType,
      address,
      pincode,
      date: date ? new Date(date) : new Date(), // Use provided date or current date
      userId: req.session.user.id
    });

    await newIssue.save();
    // Instead of redirect, render the same page with success=true
    res.render('report_issue', { success: true, user: req.session.user, deletedMsg: null });
  } catch (error) {
    console.error('Cloudinary Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

// open first page
app.get('/', async (req, res) => {
   try {
    const visitorCount = await Signin.countDocuments();
    const issuesReported = await Issue.countDocuments();
    const issuesResolved = await Issue.countDocuments({ status: 'Resolved' });
    const notAdmin = req.query.notAdmin === 'true';
    res.render('index', { visitorCount, issuesReported, issuesResolved, notAdmin });
  } catch (err) {
    res.render('index', { visitorCount: 'N/A' , issuesReported: 'N/A', issuesResolved: 'N/A', notAdmin: req.query.notAdmin === 'true' });
  }
});
// about rotute page
app.get('/about', (req, res) => {
  res.render('about');
});
// loginroute page
app.get('/login', (req, res) => {
  const message = req.query.msg || null;
  const success = req.query.success === 'true';
  res.render('login', { message, success });
});
// signin route page
app.get('/signin', (req, res) => {
  const message = req.query.msg || null;
  const success = req.query.success === 'true';
  res.render('signin', { message, success });
});
// login route/;[]
app.get('/api/signin-login', (req, res) => {
  const message = req.query.msg || null;
  const success = req.query.success === 'true';
  res.render('login', { message, success });
});
// /report-an-issue-now
app.get('/report-an-issue-now',login_or_not,(req, res) => {
  //check if user is authenticated 
  res.render('report_issue', {success: req.query.success === 'true', user: req.session.user, deletedMsg: null });
});


// Route to resolve an issue (set status to 'Resolved')
app.post('/admin/resolve/:id', login_or_not, async (req, res) => {
  try {
    const issueId = req.params.id;
    await Issue.findByIdAndUpdate(issueId, { status: 'Resolved' });
    res.redirect('/api/admin');
  } catch (error) {
    console.error('Error resolving issue:', error);
    res.status(500).send('Internal Server Error');
  }
});
// Route to delete an issue by admin
app.post('/admin/delete/:id', login_or_not, async (req, res) => {
  try {
    const issue = await Issue.findByIdAndDelete(req.params.id);
    if (issue) {
      // Notify the user by setting a flag in session or redirect with query param
      // For now, redirect to admin with a message, and also set a flag for the user
      // Option 1: If you want to show the message on the user's report page next time they visit:
      // You could store a deleted flag in the session for the user, but here we'll use a query param for demo
      res.redirect('/api/admin?msg=Issue deleted successfully');
      // Optionally, you could email the user here using nodemailer
      // Optionally, you could redirect the user to /api/report-an-issue-now?deleted=true
    } else {
      res.redirect('/api/admin?msg=Issue not found');
    }
  } catch (err) {
    console.error('Error deleting issue:', err);
    res.status(500).send('Server error');
  }
});
app.post('/api/signin', signin)
app.post('/api/login', login);


 

// POST logout route for form submissions
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.clearCookie('userRole');
    res.clearCookie('userEmail');
    res.redirect('/');
  });
});

app.get('/check-session', (req, res) => {
  res.json(req.session.user || 'No session');
});

// Route to show reports for the logged-in user
app.get('/my-reports', login_or_not, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const myIssues = await Issue.find({ userId }).sort({ date: -1 });
    const username= req.session.user.fullname; // Get username from session
    res.render('my_reports', { user: req.session.user, issues: myIssues , username});
  } catch (error) {
    console.error('Error fetching user reports:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Forgot Password - Step 1: Render page
app.get('/forgot-password', (req, res) => {
  res.render('forgot_password', { step: 'email', msg: null, msgType: '' });
});

// Forgot Password - Step 2: Send OTP
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await Signin.findOne({ email });
  if (!user) {
    return res.render('forgot_password', { step: 'email', msg: 'Email not found.', msgType: 'error' });
  }
  // Generate 4-digit OTP
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  req.session.resetEmail = email;
  req.session.otp = otp;
  // Send OTP mail
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    },
      tls: {
    rejectUnauthorized: false
  }
  });
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'undoBharat Password Reset OTP',
    text: `Your OTP for password reset is: ${otp}`
  });
  res.render('forgot_password', { step: 'otp', msg: 'OTP sent to your email.', msgType: 'success' });
});

// Forgot Password - Step 3: Verify OTP
app.post('/verify-otp', (req, res) => {
  const { otp } = req.body;
  if (otp === req.session.otp) {
    res.render('forgot_password', { step: 'reset', msg: 'OTP verified. Enter new password.', msgType: 'success' });
  } else {
    res.render('forgot_password', { step: 'otp', msg: 'Invalid OTP. Try again.', msgType: 'error' });
  }
});

// Forgot Password - Step 4: Reset Password
app.post('/reset-password', async (req, res) => {
  const { password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const email = req.session.resetEmail;
  if (!email) {
    return res.render('forgot_password', { step: 'email', msg: 'Session expired. Try again.', msgType: 'error' });
  }

  await Signin.findOneAndUpdate({ email }, { password: hashedPassword });
  req.session.otp = null;
  req.session.resetEmail = null;
  res.render('login', { message: 'Password changed successfully. Please log in.', success: true });
});

// Route to show a single report's details
app.get('/admin/report/:id',  async (req, res) => {
  try {
    const issue = await Issue.findById(req.params.id);
    if (!issue) return res.status(404).send('Report not found');
    res.render('report_details', { issue });
  } catch (err) {
    console.error('Error loading report details:', err);
    res.status(500).send('Server error');
  }
});

// Route for /admin link from home page
app.get('/admin', (req, res) => {
  if (req.session.user && req.session.user.role === 'admin') {
    return res.redirect('/api/admin');
  } else {
    // Not admin, redirect to home with message
    return res.redirect('/?notAdmin=true');
  }
});

// how it works page
app.get('/How-it-works', (req, res) => {
  res.render('How-it-works');  
  });
 

  
  // Send OTP
  app.post('/api/send-otp', async (req, res) => {
      const { email } = req.body;
      if (!email) return res.json({ success: false, message: 'Email required' });
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      otps[email] = otp;
  
      // Send email (configure your transporter with your credentials)
      const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
              user: process.env.EMAIL_USER,
              pass: process.env.EMAIL_PASS
          },
           tls: {
        rejectUnauthorized: false
    }
      });
      try {
          await transporter.sendMail({
              from: process.env.EMAIL_USER,
              to: email,
              subject: 'Your OTP for UndoBharat Signup',
              text: `Your OTP is: ${otp}`
          });
          res.json({ success: true });
      } catch (err) {
          res.json({ success: false, message: 'Failed to send OTP' });
          console.error('Error sending OTP:', err);
      }
  });
  
  // Verify OTP
  app.post('/api/verify-otp', (req, res) => {
      const { email, otp } = req.body;
      if (otps[email] && otps[email] === otp) {
          delete otps[email];
          res.json({ success: true });
      } else {
          res.json({ success: false, message: 'Invalid OTP' });
      }
  });
app.get('/api/get-mails', async (req, res) => {
  try {
    const users = await Signin.find({}, 'email role'); // Fetch only email and role fields
    res.json(users.map(user => ({ email: user.email, role: user.role })));
  } catch (err) {
    console.error('Error fetching emails:', err);
    res.status(500).json({ error: 'Failed to fetch emails' });
  }
});

// Restore session from JWT if session is missing but token exists
app.use((req, res, next) => {
  if (!req.session.user && req.cookies.token) {
    try {
      const decoded = jwt.verify(req.cookies.token, JWT_SECRET);
      req.session.user = {
        id: decoded.id,
        fullname: decoded.fullname,
        email: decoded.email,
        role: decoded.role,
        isAuthenticated: true
      };
      req.session.IsAuthenticated = true;
    } catch (err) {
      // Invalid token, clear cookie
      res.clearCookie('token');
    }
  }
  next();
});

// ✅ Start server
app.listen(port, () => {
  console.log(`🚀 Server started at http://localhost:${port}`);
});
