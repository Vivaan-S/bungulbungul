const Database = require("replpersist");
const express = require("express");
const cookieParser = require('cookie-parser')
const app = express();
app.use(cookieParser())
app.use(function(req,res,next){
  let loggedIn = cookieAuth(req.cookies.auth)
  req.loggedIn=Boolean(loggedIn)
  loggedIn?(req.username =loggedIn.name,req.account=loggedIn):0
  
  next()
})
app.use(express.urlencoded({extended:1}))
const sha = require("sha2");
const c = require("crypto");
userDB = new Database("users",1);
saltDB = new Database("salt",1,generateToken())
saltDB.upload()
function generateToken(){
  return c.randomBytes(128).toString("hex")
}
function hash(input){
  return sha.sha512(input).toString("base64")
}
function hashPassword(password){
  return hash(hash(saltDB.data+password))
}
function isPassword(user,password){
  let acc = userDB.data.fCustom("name",user.toLowerCase());
  return acc&&acc.password==hash(hash(saltDB.data+password+acc.name))
}
function cookieAuth(cookie){
  if(!cookie)return
  return userDB.data.fCustom("authHash",hash(cookie))
}
app.get("/",function(req,res){
  if(!req.loggedIn){
    res.sendFile(__dirname+"/signup.html");
    return
  }
  res.send(`Welcome, ${req.username}`)
})
app.get("/login",function(_,res){res.sendFile(__dirname+"/login.html")})
app.get("/signup",function(_,res){res.sendFile(__dirname+"/signup.html")})
app.post("/signup", function(req,res){
  function error(error){
    res.send(`<script>alert('Error: ${error}');location="/signup"</script>`)
  }
  let body = req.body
  let pw = String(body.pw)
  let name = String(body.name)
  if(!pw.match(/^.{3,50}$/)){
  error("invalid password")
  return
  }
  if(!name.match(/^[a-zA-Z0-9_].{1,20}$/)){
    error("Invalid name");
    return
  }
  if(userDB.data.f(name.toLowerCase())){
    error("name used");
    return
  }
  let token = generateToken()+Date.now()
  let data = {
    name:name.toLowerCase(),
    authHash:hash(token),
    password:hashPassword(pw+name.toLowerCase())
  }
  userDB.data.push(data)
  res.cookie("auth",token,{maxAge:432000000})
  res.redirect("/")
})
app.post("/login", function(req,res){
  let body = req.body;
  let pw = String(body.pw);
  let name = String(body.name).toLowerCase();
  var acc = userDB.data.f(name)
  if(!isPassword(name,pw)){
    res.send("<script>alert('Incorrect Username or Password');location='/login'</script>");
    return
  }
  let token = generateToken()+Date.now()
  acc.authHash = hash(token)
  res.cookie("auth",token,{maxAge:43299999999999999999999999999999})
  res.redirect("/")
})
app.listen(3000)
