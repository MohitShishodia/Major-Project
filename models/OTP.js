
const mongoose = require("mongoose");

const OTPSchema = new mongoose.Schema({
    email:{
        type:String,
        required:true,
    },
    otp:{
        type:String,
        required:true,
    },
    createdAt:{
        type:Date,
        default:Date.now(),
        expires:5*60,
    },
    
});

//we have to create the pre middleware after the schema before model
//a function -> to send mails

async function sendVerificationEmail(email,otp){
    try{
        const mailResponse= await mailSender(email,"Verification Email From StudyNotion",otp);
        console.log("Email send Successfully",mailResponse);
    }
    catch(error){
        console.log("error occured while sending Email",error);
        throw error;
    }
}

//revise

OTPSchema.pre("save",async function(next){
    //this is for current otp for email
    await sendVerificationEmail(this.email,this.otp);
    next();
})


module.exports= mongoose.model("OTP",OTPSchema);