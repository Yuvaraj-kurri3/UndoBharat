const express = require('express');
const router = express.Router();
const multer = require('multer');
const Issue = require('../models/Issue');

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});

const upload = multer({ storage });

// Route: POST /api/user/report
router.post('/report', upload.single('image'), async (req, res) => {
  try {
    const {
      fullName,
      contactInfo,
      issueTitle,
      issueDescription,
      category,
      village,
      mandal,
      district
    } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: 'Image upload is required.' });
    }

    const newIssue = new Issue({
      user: {
        name: fullName,
        contact: contactInfo
      },
      title: issueTitle,
      description: issueDescription,
      category: category,
      imageUrl: `/uploads/${req.file.filename}`,
      location: {
        village,
        mandal,
        district
      }
    });

    const savedIssue = await newIssue.save();
    res.status(201).json({ message: 'Issue reported successfully.', data: savedIssue });
  } catch (err) {
    console.error('Error submitting issue:', err);
    res.status(500).json({ error: 'Failed to submit the issue.' });
  }
});

module.exports = router;
