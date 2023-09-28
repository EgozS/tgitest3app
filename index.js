const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const config = require('./config.json');

const app = express();
const port = 8080;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('views', './views');
app.set('view engine', 'ejs');

//session setup
app.use(session({
    secret: config.secret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

//this function will auth the token
function authenticateToken(req, res, next) {
    // Get the token from the request headers
    const token = req.session.token;
  
    if (!token) {
      // If no token is provided, return a 401 Unauthorized response
      res.redirect('/login?err=401');
      return;
    }
  
    // Verify the token
    jwt.verify(token, config.secret, (err, user) => {
      if (err) {
        // If the token is not valid, return a 403 Forbidden response
        res.redirect('/login?err=403');
        return;
      }
  
      // If the token is valid, you can access the user information in 'user'
      req.user = user;
      next();
    });
}

function getTokenExp(token)
{
    try
    {
        var decoded = jwt.decode(token);
        if(!decoded || !decoded.exp) //bad token
        {
            return null; 
        }
        
        //return the expiration date
        const expDate = new Date(decoded.exp * 1000);
        return expDate;
    }
    catch (err)
    {
        return null;
    }
}

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/protected-route', authenticateToken, (req, res) => {
    res.send(`Hello ${req.user.username}, Your token expires at: ${getTokenExp(req.session.token)}`);
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    //register the user
    axios.get(config.register, {
        params: {
            username: username,
            email: email,
            password: password
        }
    })
    .then((response) => {
        if(response.status === 200) {
            res.redirect('/login');
        }
        else
        {
            res.redirect(`/register?err=${response.response.data.message}`);
        }
    })
    .catch((err) => {
        res.redirect(`/register?err=${err.response.data.message}`);
    });
});

app.post('/login', (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    axios.get(config.login, {
        params: {
            username: username,
            password: password
        }
    })
    .then((response) => {
        if(response.status === 200 && response.data.token) {
            req.session.token = response.data.token;
            res.redirect('/protected-route');
        }
        else
        {
            
            res.redirect(`/login?err=${response.response.data.message}`);
        }
    })
    .catch((err) => {
        res.redirect(`/login?err=${err.response.data.token}`);
    });
});

app.listen(port, () => {
    console.log(`webapp running on: localhost:${port}`);
});