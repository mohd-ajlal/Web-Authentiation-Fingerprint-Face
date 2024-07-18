const express = require('express');
const {generateRegistrationOptions} = require('@simplewebauthn/server')

const PORT=3000;
const app = express();

app.use(express.static('./public'))
app.use(express.json())

const userStore = {}

const challengeStore= {}

app.post('/register', (req, res)=>{
    const {username, password} = req.body;
    const id = `user_${Date.now()}`

    const user = {
        id,
        username,
        password
    }

    userStore[id] = user;

    console.log(`Register successful `, userStore[id]);

    return res.json({id})
})

app.post('/register-challenge', async(req, res)=>{
     // in real world application there will be token so we can see from token is this a valid id
    //  since we dont have jwtwebtoken setup in this project we are just sending id
     const {userId} = req.body;


     if(!userStore[userId]) return res.status(404).json({error:"User not found"})

    const user = userStore[userId]

    const challengePayload = await generateRegistrationOptions({
        rpID:'localhost',
        rpName:'My localhost Machine',
        userName:user.username,
    })

    challengeStore[userId] = challengePayload.challenge

    return res.json({options:challengePayload})
})

app.listen(PORT, ()=>console.log('Server started on port '+PORT));