const crypto = require('crypto')

const User = require('../models/user');
const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const sendGridTransport = require('nodemailer-sendgrid-transport')

const transporter = nodemailer.createTransport(sendGridTransport({
  auth: {
    api_key: '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'
  }
}))

exports.getLogin = (req, res, next) => {
  let message = req.flash('error')
  if(message.length>0){
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error')
  if(message.length>0){
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email
  const pass = req.body.password
  User.findOne({email: email})
    .then(user => {
      if(!user){
        req.flash('error', 'Invalid email or password')
        return res.redirect('/login')
      }
      bcrypt.compare(pass, user.password)
        .then(doMatch => {
          if(doMatch){
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }
          res.redirect('/login')
        })
        .catch(err=>{
          console.log(err)
          res.redirect('/login')
        })
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email
  const password = req.body.password
  const confirm = req.body.confirmPassword

  User.findOne({email: email})
    .then(userDoc => {
      if(userDoc){
        req.flash('error', 'Email already registered')
        return res.redirect('/signup')
      }
      return bcrypt.hash(password, 12)
    })
    .then(hashed => {
      const user = new User({
        email: email,
        password: hashed,
        cart: {items: []}
      })
      return user.save()
    })
    .then(result => {
      res.redirect('/login')
      return transporter.sendMail({
        to: email,
        from: 'shop@node-complete.com',
        subject: 'Signup Verification',
        html: '<h1>You signed up!</h1>'
      })
    })
    .catch(err=>console.log(err))
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req,res, next) => {
  let message = req.flash('error')
  if(message.length>0){
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  })
}

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer)=>{
    if(err) {
      console.log(err)
      return res.redirect('/reset')
    }
    const token = buffer.toString('hex')
    User.findOne({email: req.body.email})
      .then(user=>{
        if(!user){
          req.flash('error', 'No account with that email found.')
          return res.redirect('/reset')
        }
        user.resetToken = token
        user.resetTokenExp = Date.now() + 3600000
        return user.save()
      })
      .then(result=>{
        res.redirect('/')
        transporter.sendMail({
          to: req.body.email,
          from: 'shop@node-complete.com',
          subject: 'Password reset confirmation',
          html: `
            <p>You have requested a password reset</p>
            <p>Click on this <a href="http://localhost:3000/new-password/${token}">link</a> to confirm password reset.</p>
          `
        })
      })
      .catch(err=>console.log(err))
  })
}

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token
  User.findOne({
    resetToken: token, 
    resetTokenExp: {$gt: Date.now()}
  })
    .then(user => {
      let message = req.flash('error')
      if(message.length>0){
        message = message[0]
      } else {
        message = null
      }
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'Update Password',
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token
      });
    })
    .catch(err=>console.log(err))
};

exports.postNewPassword = (req,res,next) => {
  const newPassword = req.body.password
  const userId = req.body.userId
  const passwordToken = req.body.passwordToken
  let resetUser

  User.findOne({
    resetToken: passwordToken,
    resetTokenExp: {$gt: Date.now()},
    _id: userId
  })
    .then(user=>{
      resetUser = user
      return bcrypt.hash(newPassword, 12)
    })
    .then(hashedPass => {
      resetUser.password = newPassword
      resetUser.resetToken = null
      resetUser.resetTokenExp = undefined
      return resetUser.save()
    })
    .then(result => res.redirect('/'))
    .catch(err=>console.log(err))
}