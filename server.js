const express = require('express');
const session = require('express-session');
const flash = require('express-flash');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const app = express();

mongoose.connect('mongodb://localhost/dojo_secrets');

app.set('trust proxy', 1);
app.use(session({
  secret: "secret key!",
  saveUninitialized: true,
  resave: true,
  cookie: { maxAge: 60000 }
}));

app.use(bodyParser.urlencoded({extended: true}));
app.use(flash());

app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, "Email is required!"],
    unique: [true, "Email is already taken by another user"],
    validate: {
      validator: (email)=>{
        let emailRegex = /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/;
        return emailRegex.test(email);
      },
      message: '"{VALUE}" is not a valid email!'
    }
  },
  password: {
    type: String,
    required: [true, "Password is required."],
    minlength: [7, "Password must include atleast 7 characters"],
  }
});

mongoose.model('User', UserSchema);

const CommentSchema = new mongoose.Schema({
  secret_id: String,
  content: {
    type: String,
    required: [true, "Comment text is required!"],
    minlength: [3, "Comment must include atleast 3 characters!"]
  }
});

mongoose.model('Comment', CommentSchema);

const SecretSchema = new mongoose.Schema({
  author_id: String,
  content: {
    type: String,
    required: [true, "Comment text is required!"],
    minlength: [3, "Comment must include atleast 3 characters!"]
  },
  comments: [CommentSchema]
});

mongoose.model('Secret', SecretSchema);

const User = mongoose.model('User');
const Comment = mongoose.model('Comment');
const Secret = mongoose.model('Secret');

app.get('/', (req, res)=>{

  if(req.session.user_id){
    res.render('secrets', {'session': req.session});
    res.redirect('/secrets');
  }

  res.render('index', {'session': req.session});
})

app.get('/logout', (req, res)=>{
  if(req.session.user_id){
    req.session.destroy();
  }
  
  res.redirect('/');
})

app.get('/secrets', (req, res)=>{
  if(req.session.user_id){
    Secret.find({}, (err, secrets)=>{
      if(err){
        console.log("error querying db");
        res.redirect('/');
      }
      else{
        res.render('secrets', {'session': req.session, 'secrets': secrets});
      }
    });
  }else{
    req.flash("login_errors", "Session has expired.");
    res.redirect('/');
  }
  
})

app.get('/secrets/:id', (req, res)=>{
  console.log("You clicked my secret! ", req.params.id);
  
  Secret.findById(req.params.id, (err, secret)=>{
    if(err){
      console.log("Issue getting secret details");
    }else{
      console.log(secret.comments);

      res.render('details', {'session': req.session, 'secret': secret})
    }
  })
})

app.post('/login', (req, res)=>{
  User.findOne({email: req.body.email}, (err, user)=>{
    if(err){
      console.log(err);
      req.flash("login_errors", "User credentials not found or invalid!");
      res.redirect('/');
    }
    
    if(user){
      console.log(user);

      bcrypt.compare(req.body.password, user.password)
        .then(result=>{
          console.log(result);

          req.session.user_id = user.id;

          console.log("Session_UserID: ", req.session.user_id);
    
          res.redirect('/secrets');
        })
        .catch(error=>{
          console.log(error);
        
          req.flash("login_errors", "User credentials not found or invalid!");
          res.redirect('/');
        })
    }else{
      req.flash("login_errors", "User credentials not found or invalid!");
      res.redirect('/');
    }
  });
})

app.post('/registration', (req, res)=>{
  if(req.body.password && (req.body.password === req.body.password_confirm)){
    
    bcrypt.hash(req.body.password, 10, (err, hashed)=>{
      if(err){
        console.log(err);

        req.flash("registration_errors", "Error processing registration.");
        res.redirect('/');
      }else{
        let user = new User({
          email: req.body.email,
          password: hashed
        });

        user.save(err=>{
          if(err){
            
            for(var error in err.errors){
              console.log(err.errors[error].message);
              req.flash("registration_errors", err.errors[error].message);
            }
            res.redirect('/');
          }else{
            req.session.user_id = user.id;
    
            res.redirect('/secrets');
          }
        })
      }
    })
  }else{
    req.flash("registration_errors", "Passwords do not match!");
    res.redirect('/');
  }
})

//Create a new secret
app.post('/secrets/secret_new', (req, res)=>{

  let secret = new Secret({
    author_id: req.session.user_id,
    content: req.body.secret_content,
  }).save(err=>{
    if(err){
      console.log("Error creating secret!");

      for(var error in err.errors){
        req.flash("secret_errors", err.errors[error].message);
      }

      res.redirect('/secrets');
    }else{
      res.redirect('/secrets');
    }
  })
})

//Post new comment for a secret
app.post('/secrets/:id/new', (req, res)=>{
  Secret.findByIdAndUpdate(req.params.id, 
    {$push: 
      {
        comments: new Comment({
          secret_id: req.params.id,
          content: req.body.comment_content
        })
      }
    }, 

    (err, status)=>{

    if(err){
      console.log("Error adding comment!");
      console.log(err);

    }else{
      res.redirect('/secrets/' + req.params.id);
    }

  });
})

//Delete secret
app.post('/secrets/:id/delete', (req, res)=>{
  Secret.findByIdAndRemove(req.params.id, (err, state)=>{
    if(err){
      console.log("Error deleting document ", req.params.id);

    }else{
      res.redirect('/secrets');
    }
  })
})

app.listen(7777, ()=>{
  console.log("Express app listening on port 7777");
})