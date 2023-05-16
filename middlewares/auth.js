const jwt =require("jsonwebtoken");
require("dotenv").config();
const User=require("../models/User");
//auth

exports.auth=async(req,res,next)=>{
    try{
        //extact token
        const token=req.cookies.token
                        ||req.body.token
                        ||req.header("Authorisation").replace("Bearer ","");
        
        //if token is missing
        if(!token){
            return res.status(401).json({
                success:false,
                message:'Token is missing',
            });
        }
        
        //verify the token using secret key
        try{
            const decode=await jwt.verify(token,process.env.JWT_SECRET);
            console.log(decode);
            req.user=decode;
        }
        catch(error){
            //verification -issue
            return res.status(401).json({
                success:false,
                message:'Token is invalid',
            });
        }
        next();

    }
    catch(error){
        return res.status(401).json({
            success:false,
            message:'something is wrong while validating ',
        });
    }
}



//isStudent
exports.isStudent=async(req,res,next) =>{
    try{
        if(req.user.accountType !== "Student"){
            return res.status(401).json({
                success:false,
                message:'This is protected route for student only',
            });
        }
        next();
    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:'User cannot Verified please try again',
        });
    }
}

//isInsturctor
exports.isInstructor=async(req,res,next) =>{
    try{
        if(req.user.accountType !== "Instructor"){
            return res.status(401).json({
                success:false,
                message:'This is protected route for instructor only',
            });
        }
        next();
    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:'User cannot Verified please try again',
        });
    }
}


//isAdmin

exports.isAdmin=async(req,res,next) =>{
    try{
        if(req.user.accountType !== "Admin"){
            return res.status(401).json({
                success:false,
                message:'This is protected route for admin only',
            });
        }
        next();
    }
    catch(error){
        return res.status(500).json({
            success:false,
            message:'User cannot Verified please try again',
        });
    }
}
