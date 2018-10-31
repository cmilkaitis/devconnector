const express = require('express');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');

const router = express.Router();

// Load Input Validation
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');

const User = require('../../models/User');
const key = require('../../config/keys').secretOrKey;

// @route   GET api/users/test
// @desc    Test users route
// @access  Public
router.get('/', (req, res) => {
  res.json({ msg: 'users route' });
});

// @route   GET api/users/reqister
// @desc    Register a user
// @access  Public
router.post('/register', (req, res) => {
  const { name, email, password } = req.body;
  const { errors, isValid } = validateRegisterInput(req.body);

  // Check validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  User.findOne({ email }).then(user => {
    if (user) {
      errors.email = 'Email already exists';
      return res.status(400).json(errors);
    } else {
      // Create User Avatar with base settings
      const avatar = gravatar.url(email, {
        s: 200,
        r: 'pg',
        d: 'mm'
      });

      // Create the User
      const newUser = new User({ name, email, avatar, password });

      // Hash the password
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;

          // Set the hased password on the User object
          newUser.password = hash;
          newUser
            .save()
            .then(user => res.json(user))
            .catch();
        });
      });
    }
  });
});

// @route   GET api/users/login
// @desc    Login User and return the web token
// @access  Public
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const { errors, isValid } = validateLoginInput(req.body);

  // Check validation
  if (!isValid) {
    return res.status(400).json(errors);
  }

  // Find the user by email
  User.findOne({ email }).then(user => {
    if (!user) {
      return res.status(404).json({ errors });
    }
    // Check if password is match and return TOKEN
    bcrypt.compare(password, user.password).then(isMatch => {
      if (isMatch) {
        // User matched name and password
        const payload = { id: user.id, name: user.name, avatar: user.avatar };
        jwt.sign(payload, key, { expiresIn: 3600 }, (err, token) => {
          res.json({ success: true, token: `Bearer ${token}` });
        });
      } else {
        return res.status(400).json({ errors });
      }
    });
  });
});

// @route   GET api/users/current
// @desc    Return current user
// @access  Private
router.get(
  '/current',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.json(req.user);
  }
);

module.exports = router;
