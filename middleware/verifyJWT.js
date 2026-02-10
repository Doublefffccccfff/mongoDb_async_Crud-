const jwt = require("jsonwebtoken");

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    
    // console.log('Auth Header:', authHeader); // ← Add this
    
    if (!authHeader?.startsWith("Bearer ")) {
        console.log('No Bearer token');
        return res.sendStatus(401);
    }
      
    const token = authHeader.split(" ")[1];
    // console.log('Extracted Token:', token.substring(0, 20) + '...'); // ← Add this (shows first 20 chars)
    
    jwt.verify(
        token,
        process.env.ACCESS_TOKEN_SECRET,
        (err, decoded) => {
            if (err) {
                console.log('JWT Verification Failed:', err.message); // ← Add this
                return res.sendStatus(403); // This is likely where you're failing
            }
            // console.log('JWT Verified Successfully! User:', decoded.UserInfo.username); // ← Add this
            req.user = decoded.UserInfo.username;
            req.roles = decoded.UserInfo.roles;
            next();
        }   
    );
};

module.exports = verifyJWT;