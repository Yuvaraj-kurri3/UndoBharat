const express = require('express');
const router = express.Router();
const Issue = require('../models/Issue');

// GET all issues (Admin dashboard)
router.get('/issues', async (req, res) => {
  try {
    const issues = await Issue.find().sort({ createdAt: -1 });
    res.status(200).json(issues);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching issues', error });
  }
});

// PUT update issue status
router.put('/issues/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const updatedIssue = await Issue.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    if (!updatedIssue) {
      return res.status(404).json({ message: 'Issue not found' });
    }
    res.status(200).json(updatedIssue);
  } catch (error) {
    res.status(500).json({ message: 'Error updating status', error });
  }
});

module.exports = router;
