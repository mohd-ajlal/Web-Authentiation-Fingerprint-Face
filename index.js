const express = require('express');
const {generateRegistrationOptions, verifyRegistrationResponse,  generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server')
const crypto = require("node:crypto");


if(!globalThis.crypto){
    globalThis.crypto = crypto;
}

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
        rpID: 'localhost',
        rpName: 'My Localhost Machine',
        attestationType: 'none',
        userName: user.username,
        timeout: 30_000,
    })

    challengeStore[userId] = challengePayload.challenge

    return res.json({options:challengePayload})
})

app.post('/register-verify', async (req, res) => {
    const { userId, cred }  = req.body
    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })

    const user = userStore[userId]

    const challenge = challengeStore[userId]
    const verificationResult = await verifyRegistrationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
    })

    if (!verificationResult.verified) 
        return res.json({ error: 'could not verify it. Please try again' });
    userStore[userId].passkey = verificationResult.registrationInfo

    return res.json({ verified: true })

})

app.post('/login-challenge', async (req, res) => {
    const { userId } = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    
    const opts = await generateAuthenticationOptions({
        
        rpID: 'localhost',

    })
    challengeStore[userId] = opts.challenge

    return res.json({ options: opts })
})


app.post('/login-verify', async (req, res) => {
    const { userId, cred }  = req.body

    if (!userStore[userId]) return res.status(404).json({ error: 'user not found!' })
    const user = userStore[userId]
    const challenge = challengeStore[userId]

    const result = await verifyAuthenticationResponse({
        expectedChallenge: challenge,
        expectedOrigin: 'http://localhost:3000',
        expectedRPID: 'localhost',
        response: cred,
        authenticator: user.passkey
    })

    if (!result.verified) return res.json({ error: 'something went wrong' })

    return res.json({ success: true, userId })
})

app.listen(PORT, ()=>console.log('Server started on port '+PORT));