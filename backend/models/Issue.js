const mongoose = require('mongoose');

const issuereport = new mongoose.Schema({
  name: { type: String, required: true },
  mobile:{ type: String, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  images: [{ type: String }], // Array of image URLs
  problemType: { type: String, required: true },
  address: { type: String, required: true },
  pincode: { type: Number, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, default: 'Not Resolved' }
});

module.exports = mongoose.model('Issue', issuereport);
