const User=require("..models/User");
const OTP=require("../models/OTP");
const otpGenerator=require("otp-generator");
const bcrypt =require("bcrypt");
const jwt =require("jsonwebtoken");
require("dotenv").config();

//send otp

exports.sendOTP=async(req,res) =>{

    try{
        //fetch email from the req
        const {email}=req.body;

        //check if user is already registered
        const checkUserPresent=await User.findOne({email});

        //if already registered
        if(checkUserPresent)
        {
            return res.status(401).json({
                success:false,
                message:'User already registered',
            })
        }

        //generate otp

        var otp=otpGenerator.generate(6,{
            upperCaseAlphabets:false,
            lowerCaseAlphabets:false,
            specialChars:false,
        });

        console.log("Otp generated",otp);

        //check unique otp or not
        const result=await OTP.findOne({otp:otp});

        while(result){
            otp=otpGenerator.generate(6,{
                upperCaseAlphabets:false,
                lowerCaseAlphabets:false,
                specialChars:false,
            });
            result =await OTP.findOne({otp:otp});
        }

        const otpPayload={email,otp};

        //create an entry for OTP

        const otpBody=await OTP.create(otpPayload);

        console.log(otpBody);

        //return response successfull
        res.status(200).json({
            success:true,
            message:'OTP Sent Successfully',
            otp,
        })
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:error.message,
        })
    }

};



//sign up 
exports.signUp=async(req,res)=>{
    try{
        //data fetch fromm req ki body
        const {
            firstName,
            lastName,
            email,
            password,
            confirmPassword,
            accountType,
            contactNumber,
            otp
        }=req.body;
        //validate krlo
        if(!firstName || !lastName || !email || !password || !confirmPassword || !otp){
            return res.status(403).json({
                success:true,
                message:"All fields are required",
            })
        }
        //2 password match krlo
        if(password != confirmPassword){
            return res.status(400).json({
                success:false,
                message:"Password does not match with confirmPassword"
            });
        }

        //check user is already registered
        const existingUser=await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success:false,
                message:" User already Registered"
            });
        }
        //find most recent OTP stored for the user
        const recentOtp=await OTP.find({email}).sort({createdAt:-1}).limit(1);
        console.log(recentOtp);
        //validate OTP
        if(recentOtp.length==0)
        {
            //otp found
            return res.status(400).json({
                success:false,
                message:"Otp found"
            })

        }else if(otp !== recentOtp.otp){
            //Invalid Otp
            return res.status(400).json({
                success:false,
                message:"Invalid OTP "
            });
        }

        //Hash password
        const hashedPassword=await bcrypt.hash(password,10);

        //entry created in DB
        const profileDeatils=await Profile.create({
            gender:null,
            dateOfBirth:null,
            about:null,
            contactNumber:null,
        });

        const user=await User.create({
            firstName,
            lastName,
            email,
            contactNumber,
            password:hashedPassword,
            accountType,
            additionalDetails:profileDeatils._id,
            image:`https://api.dicebear.com/5.x/initials/svg?seed=${firstname} ${lastName}`,
        })  

        //return res
        return res.status(200).json({
            success:true,
            message:"User is registered Successfully",
            user,
        });

    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:true,
            message:"User can not be registered Successfully", 
        });
    }

}



// login
exports.login=async(req,res)=>{
    try{
        //get data from req body
        const {email,password}=req.body;

        //validation data
        if(!email || !password)
        {
            return res.status(403).json({
                success:false,
                message:"All field are required please try again",
            });
        }
        //user check exist or not
        const user =await User.findOne({email});
        if(!user){
            return res.status(403).json({
                success:false,
                message:"User is not Registered,please signup first",
            });
        }
        //generate JWT,after password matching
        if(await bcrypt.compare(password,user.password)){
            const payload={
                email:user.email,
                id:user.id,
                accountType:user.accountType,
            }
            const token=jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn:"2h",
            });
            user.token=token;
            user.password=undefined;

            //create cookie and send response
            const options={
                expires:new Date(Date.now() + 3*24*60*60*1000),
                httpOnly:true,
            }
            res.cookie("token",token,options).status(200).json({
                success:true,
                token,
                user,
                message:"logged in successfully",
            })
        }
        else {
            return res.status(401).json({
                success:false,
                message:"Password is incorrect",
            }); 
        }
    }

    catch(error){
        return res.status(500).json({
            success:false,
            message:"Login Failure try again",
        });
    }
}





//change password
exports.changePassword=async(req,res)=>{
    //get data from the req body
    //get oldpassword,newpassword,confirm password
    //validation

    //update pwd in DB
    //send mail-password updated
    //return response
}
