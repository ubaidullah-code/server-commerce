import express from 'express';
import 'dotenv/config'
import cors from 'cors'
import db from './db.mjs'
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'
const app = express()
const PORT  = 5004;

app.use(express.json())
app.use(cors())

const SECRET = process.env.SECRET_TOKEN

// user get API
app.get('/', async(req, res)=>{
  try {
        let result = await db.query('SELECT * FROM users')
        res.status(200).send({message: "user Founded" , data: result.rows })
    } catch (error) {
      console.log("error", error)
        res.status(500).send({message: "Internal Server Error"})
    }

})
// sign-up API
app.post('/sign-up', async(req,res)=>{
let {first_name , last_name , email ,password}= req.body;
if(!first_name || !last_name || !email || !password){
  res.status(400).send({message : "Required Perameter is Missing"})
  return
}

email = email.toLowerCase()
const SignCheck = `SELECT * FROM users WHERE email = $1`
const SignValue = [email]
try {
  //email check for users
  const result = await db.query(SignCheck,SignValue)
  if (result.rows.length) {
    res.status(400).send({message : "This email is Already Existed"});
    return; 
  }
  // add user with first_name , last_name , email ,password
  const addUser = `INSERT INTO users(first_name , last_name , email , password) VALUES ($1, $2, $3 ,$4) ` 
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const addUserValue = [first_name , last_name , email ,hash]
    const addIntoSign = await db.query(addUser,addUserValue)
    res.status(201).send({message : "User is Created"})
} catch (error) {
      console.log("error " , error)
      res.status(500).send({ message: "Internal Server Error" });
}

})

// Login api
app.post('/login',async(req, res)=>{
  let {email , password} =req.body
  if (!email ||!password) { 
    res.status(400).send({message : "Required perameter is Missing"});
    return;
  }   
  email = email.toLowerCase()
  const loginCheck = `SELECT * FROM users WHERE email = $1`
  const loginValue = [email]
  try {
    const result = await db.query(loginCheck,loginValue)
    
    if(!result.rows.length){
      res.status(400).send({message : "User doesn't Existed"})
      return;
    }
    console.log("result.rows" , result.rows[0]);

    const isMatched = await bcrypt.compare(password, result.rows[0].password); 
    console.log('isMatched', isMatched);
    
    if(!isMatched){
      res.status(401).send({message: "Email doesn't Matched"});
      return;
    }
    let token = jwt.sign({
      id : result.rows[0].user_id,
      firstName : result.rows[0].first_name,
      lastName : result.rows[0].last_name,
      email : result.rows[0].email,
      user_role : result.rows[0].user_role,
      iat : Date.now() / 1000,
      exp : (Date.now()/1000) +(1000 *60*60*24)
    }, SECRET )
    console.log("token", token)

   res.cookie('Token', token, {
            maxAge: 86400000, // 1 day
            httpOnly: true,
            secure: true
        });
        res.status(200)
        res.send({message: "User Logged in" , user: {
            user_id: result.rows[0].user_id,
            firstName: result.rows[0].first_name,
            lastName: result.rows[0].last_name,
            email: result.rows[0].email,
            phone: result.rows[0].phone,
            user_role: result.rows[0].user_role,
            profile: result.rows[0].profile,
        }})
        // res.status(200).send({message: "Testing" , result: result.rows, isMatched})

    } catch (error) {
        console.log("Error", error)
        res.status(500).send({message: "Internal Server Error"})
    }
})
// app.delete('/delete:id', async (req, res) => {
//   const { id } = req.params;
//   try {
//     const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);

//     if (result.rowCount === 0) {
//       return res.status(404).json({ error: 'User not found' });
//     }

//     res.json({ message: 'User deleted successfully', deletedUser: result.rows[0] });
//   } catch (error) {
//     console.error('Delete Error:', error);
//     res.status(500).json({ error: 'Internal Server Error' });
//   }
// });
app.listen(PORT , ()=>{
  console.log(`Server is running on port ${PORT}`);
})

