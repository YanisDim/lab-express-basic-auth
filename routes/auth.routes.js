const router = require('express').Router();
const bcrypt = require('bcryptjs');
const UserModel = require('../models/User.model')
let userInfo={}

router.get('/signin', (req, res)=>{
    res.render('auth/signin.hbs')
})

router.get('/signup', (req, res)=>{
    res.render('auth/signup.hbs')
})


router.post('/signup', (req, res, next)=> {
    const {username, email, password} = req.body

    if(!username || !email || !password){
        res.render('auth/signup.hbs', {msg: 'Please enter all fields'})
        return
    }
    const passRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/
    if (!passRe.test(password)) {
        res.render('auth/signup.hbs', {msg: 'Password must be 8 characters, must have a number, must have an uppercase letter '})
        return
    }

    const re = /^[^@ ]+@[^@ ]+\.[^@ ]+$/;
    if (!re.test(String(email).toLowerCase())) {
      res.render('auth/signup.hbs', {msg: 'Please enter a valid email format'})
      return;
    }

    const salt = bcrypt.genSaltSync(12);
    const hash = bcrypt.hashSync(password, salt);

    UserModel.create({username, email, password: hash})
        .then(() => {
            res.redirect('/')
        }).catch((err) => {
            next('You shall not pass')
        });
    
})

router.post('/signin', (req, res, next) => {
    const {email, password} = req.body

    UserModel.findOne({email})
    .then((response) => {
        if(!response){
            res.render('auth/signin.hbs', {msg: 'Learn how to spell'})
        }
        else{
            bcrypt.compare(password, response.password)
            .then((isMatching)=>{
                if(isMatching){
                    req.session.userInfo = response
                    req.app.locals.isUserLoggedIn = true
                    res.redirect('/main')
                }
                else{
                    res.render('auth/signin', {msg: 'Save your data, Gollum'})
                }
                
            })
        }

    }).catch((err) => {
        next(err)
    });
})

// custom middleware

const authorize = (req, res, next)=>{
    if(req.session.userInfo){
        next()
    }
    else{
        res.redirect('/signin')
    }
}

//protected routes
/*
router.get('/profile', authorize, (req,res,next)=>{
    const{email}= req.session.userInfo
    res.render('profile.hbs', {email})
})
*/

router.get('/main', authorize,  (req,res, next)=>{
    res.render('main.hbs')
})

router.get('/private', authorize, (req,res,next)=>{
    res.render('private.hbs')
})

router.get('/logout', (req, res, next)=>{
    req.app.locals.isUserLoggedIn = false
    req.session.destroy()
    res.redirect('/')
})








module.exports = router