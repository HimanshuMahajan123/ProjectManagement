import mongoose , {Schema} from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";


const userSchema = new Schema(
    {
        avatar : {
            type : {
                url : String,
                localPath : String
            },
            default : {
                url : "https://placehold.co/200x200",
                localPath : ""
            }
        },

        username : {
            type : String,
            required : true,
            unique : true,
            trim : true,
            lowercase : true,
            index : true
        },

        email : {
            type : String,
            required : true,
            unique : true,
            trim : true,
            lowercase : true,
        },

        fullName : {
            type : String,
            trim : true,
        },

        password : {
            type : String,
            required : [true , "Password is required"],
        },

        isEmailVerified : {
            type : Boolean,
            default : false
        },

        refreshToken : {
            type : String,
        },

        forgotPasswordToken : {
            type : String,
        },

        forgotPasswordExpiry : {
            type : Date,
        },

        emailVerificationToken : {
            type : String,
        },

        emailVerificationExpiry : {
            type : Date,
        }
    },
    { 
        timestamps : true 
    }
)

// Hash password before saving the user model(pre-save hook of mongoose)
userSchema.pre("save" , async function(next){
    if(!this.isModified("password")){
        return next();
    }

    this.password = await bcrypt.hash(this.password , 10);
    next();
})

//mongoose method to compare passwords
userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password , this.password);
}


//mongoose method to generate JWTs
userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id : this._id,
            username : this.username,
            email : this.email
        },
        process.env.ACCESS_TOKEN_SECRET,
        {expiresIn : process.env.ACCESS_TOKEN_EXPIRY}
    )
}

userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id : this._id
        },
        process.env.REFRESH_TOKEN_SECRET,
        {expiresIn : process.env.REFRESH_TOKEN_EXPIRY}
    )
}

//mongoose method to generate temporary tokens(for email verification , password reset etc) using crypto(a nodejs built-in module)
userSchema.methods.generateTemporaryToken = function(){
    const unhashedToken = crypto.randomBytes(20).toString("hex");
    const hashedToken = crypto
        .createHash("sha256")
        .update(unhashedToken)
        .digest("hex");
    const tokenExpiry = Date.now() + (10*60*1000); //20 minutes from now
    return { unhashedToken , hashedToken , tokenExpiry };
}


export const User = mongoose.model("User" , userSchema);