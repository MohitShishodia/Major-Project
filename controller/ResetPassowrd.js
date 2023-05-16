const User=require("..//models/User");
const mailSender=require("../utills/mailSender");
const bcrypt= require("bcrypt");


//resetPassword token

exports.resetPasswordToken= async(req,res) =>{
    try{
        //get email from req body
        const email=req.body.email;
        //check email exist or not
        const user=await User.findOne({email:email});

        if(!user)
        {
            return res.json({success:false,
            message:'Your Email is not registered with us'});
        } 
        //generate Token
        const token=crypto.randomUUID();
        //update user by adding token and expiration time
        const updatedDetails=await User.findOneAndUpdate(
                                        {email:email},
                                        {
                                            token:token,
                                            resetPasswordExpires:Date.now()+5*60*1000,
                                        },
                                        {new:true}); 
                                        
        //create Url 
        const url=`http://localhost:3000/update-password/${token}`
        //send mail containing the Url
        await mailSender(email,"Password Reset Link",`Password Reset Link: ${url}`);
        //return response

        return res.json({
            succcess:true,
            message:'Email sent Successfully ,please check email and change',
        });
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            succcess:false,
            message:'Something went wrong while reset password',
        });
    }

}  


//reset Password

exports.resetPassword=async(req,res)=>{

    try{
        //data fetch req comes from frontend and data insert by front end
        const {password,confirmPassword,token}=req.body;

        //validation
        if(password!==confirmPassword){
            return res.json({
                succcess:false,
                message:'Password does not match',
            });
        }

        //get userDetails from db using token
        const userDetails=await User.findOne({token:token});
        //if no entry - invalid token
        if(!userDetails)
        {
            return res.json({
                succcess:false,
                message:'token is invalid',
            });
        }
        
        //token time check
        if(userDetails.resetPasswordExpires<Date.now()){
            return res.json({
                succcess:false,
                message:'token is expired',
            });
        }
        //hash pwd
        const hashedPassword=await bcrypt.hash(password,10);

        //password update 
        await User.findOneAndUpdate(
            {token:token},
            {password:hashedPassword},
            //new for apply new values
            {new:true},
        );
        //return response  
        return res.json({
            succcess:true,
            message:'Password reset Successfully',
        });
        }
    catch(error){
        console.log(error);
        return res.status(500).json({
            succcess:false,
            message:'Something went wrong while reset password',
        });
    }
    
}


