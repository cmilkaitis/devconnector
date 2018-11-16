const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');

const router = express.Router();

// Load Model
const Post = require('../../models/Post');
const Profile = require('../../models/Profile');

// Load Validation
const validatePostInput = require('../../validation/post');

// @route   GET api/posts/test
// @desc    Test post route
// @access  Public
router.get('/test', (req, res) => {
  res.json({ msg: 'post test route' });
});

// @route   POST api/posts/
// @desc    Create a post
// @access  Private
router.post(
  '/',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    const { errors, isValid } = validatePostInput(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }
    const newPost = new Post({
      text: req.body.text,
      name: req.body.name,
      avatar: req.body.avatar,
      user: req.user.id
    });
    newPost.save().then(post => res.json(post));
  }
);

// @route   Get api/posts/
// @desc    View all posts
// @access  Public
router.get('/', (req, res) => {
  Post.find()
    .sort({ date: -1 })
    .then(posts => res.json(posts))
    .catch(err => res.status(404).json({ nopostsfound: 'No posts found' }));
});

// @route   Get api/posts/
// @desc    View a single post by id
// @access  Public
router.get('/:id', (req, res) => {
  Post.findById(req.params.id)
    .then(post => res.json(post))
    .catch(err => res.status(404).json({ nopostfound: 'No post found' }));
});

// @route   DELETE api/posts/:id
// @desc    Remove a post by id
// @access  Private
router.delete(
  '/:id',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    // Find the correct Profile by user ID
    Profile.findOne({ user: req.user.id })
      .then(profile => {
        // Find that post in the users post array
        Post.findById(req.params.id).then(post => {
          // Make sure the user who in is requesting the delete
          if (post.user.toString() !== req.user.id) {
            return res
              .status(401)
              .json({ notauthorized: 'User not authorized' });
          }

          // Delete post
          post
            .remove()
            .then(() => res.json({ success: true }))
            .catch(err =>
              res.status(404).json({ postnotfound: 'No post found' })
            );
        });
      })
      .catch(err => res.status(404).json({ nopostfound: 'No post found' }));
  }
);

// @route   POST api/posts/like/:id
// @desc    Like a post via post id
// @access  Private
router.post(
  '/like/:id',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    // Find the correct Profile by user ID
    Profile.findOne({ user: req.user.id })
      .then(profile => {
        // Find that post in the users post array
        Post.findById(req.params.id).then(post => {
          // filter will eval to an array with id's of users who have like the post
          if (
            post.likes.filter(like => like.user.toString() === req.user.id)
              .length > 0
          ) {
            return res
              .status(400)
              .json({ alreadyliked: 'User already liked this post' });
          }

          // Add user id to likes array
          post.likes.unshift({ user: req.user.id });
          post.save().then(post => res.json(post));
        });
      })
      .catch(err => res.status(404).json({ nopostfound: 'No post found' }));
  }
);

// @route   POST api/posts/unlike/:id
// @desc    Unlike a post via post id
// @access  Private
router.post(
  '/unlike/:id',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    // Find the correct Profile by user ID
    Profile.findOne({ user: req.user.id })
      .then(profile => {
        // Find that post in the users post array
        Post.findById(req.params.id).then(post => {
          // filter will eval to an array with id's of users who have like the post
          if (
            post.likes.filter(like => like.user.toString() === req.user.id)
              .length === 0
          ) {
            return res
              .status(400)
              .json({ notliked: 'User has not liked this post' });
          }

          // Remove user id from likes array
          const removeIndex = post.likes
            .map(item => item.user.toString())
            .indexOf(req.user.id);
          //
          post.likes.splice(removeIndex, 1);

          post.save().then(post => res.json(post));
        });
      })
      .catch(err => res.status(404).json({ nopostfound: 'No post found' }));
  }
);

// @route   POST api/posts/comment/:id
// @desc    Comment on a post via post id
// @access  Private
router.post(
  '/comment/:id',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    const { errors, isValid } = validatePostInput(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }
    Post.findById(req.params.id)
      .then(post => {
        const newComment = {
          text: req.body.text,
          name: req.body.name,
          avatar: req.body.avatar,
          user: req.user.id
        };

        // Add comment to array
        post.comments.unshift(newComment);

        post.save().then(post => res.json(post));
      })
      .catch(err => res.status(404).json({ postnotfound: 'No post found' }));
  }
);

// @route   DELETE api/posts/comment/:id/:comment_id
// @desc    Delete a comment on a post via post id
// @access  Private
router.delete(
  '/comment/:id/:comment_id',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    Post.findById(req.params.id)
      .then(post => {
        //Check to see if the comment exists
        if (
          post.comments.filter(
            comment => comment._id.toString() === req.params.comment_id
          ).length === 0
        ) {
          return res
            .status(404)
            .json({ commentnotexist: 'Comment does not exist' });
        }

        // Get the remove index
        const removeIndex = post.comments
          .map(item => item._id.toString())
          .indexOf(req.params.comment_id);

        //Remove
        post.comments.splice(removeIndex, 1);
        post.save().then(post => res.json(post));
      })
      .catch(err => res.status(404).json({ postnotfound: 'No post found' }));
  }
);

// @route   POST api/posts/comment/:id
// @desc    Comment on a post via post id
// @access  Private
router.post(
  '/comment/:id',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    const { errors, isValid } = validatePostInput(req.body);
    if (!isValid) {
      return res.status(400).json(errors);
    }
    Post.findById(req.params.id)
      .then(post => {
        const newComment = {
          text: req.body.text,
          name: req.body.name,
          avatar: req.body.avatar,
          user: req.user.id
        };

        // Add comment to array
        post.comments.unshift(newComment);

        post.save().then(post => res.json(post));
      })
      .catch(err => res.status(404).json({ postnotfound: 'No post found' }));
  }
);

module.exports = router;
