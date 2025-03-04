const jwt = require('jsonwebtoken');
const { signupSchema,signinSchema, acceptedCodeSchema } = require('../middlewares/validator');
const User = require('../models/usersModel');
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing');
const transport = require('../middlewares/sendMail');
exports.signup = async (req, res) => {
    const { email, password } = req.body;
    try {
		const { error, value } = signupSchema.validate({ email, password });

		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}
		const existingUser = await User.findOne({ email });

		if (existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User already exists!' });
		}

		const hashedPassword = await doHash(password, 12);

		const newUser = new User({
			email,
			password: hashedPassword,
		});
		const result = await newUser.save();
		result.password = undefined;
		res.status(201).json({
			success: true,
			message: 'Your account has been created successfully',
			result,
		});
	} catch (error) {
		console.log(error);
	}
};

exports.signin = async (req, res) => {
    const { email, password } = req.body;
   try {
        const {error, value} = signinSchema.validate({email, password});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        const existingUser = await User.findOne({email}).select('+password');
        if(!existingUser){
            return res.status(401).json({success: false, message: 'User does not exist!'});
        }
        const result = await doHashValidation(password, existingUser.password);
        if(!result){
            return res.status(401).json({success: false, message: 'Invalid credentials'});
        }
        const token = jwt.sign({
            userId: existingUser._id,
            email: existingUser.email,
            verified: existingUser.verified

        }, process.env.TOKEN_SECRET, {expiresIn: '8h'}
    );
        res.cookie('Authorization', 'Bearer ' + token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === 'production',
        secure: process.env.NODE_ENV === 'production',
    }).json({
        success: true,
        token,
        message: 'logged in successfully',
    });
   } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
   }
}

exports.signout = async (req, res) => {
    res
        .clearCookie('Authorization')
        .status(200)
        .json({success: true, message: 'Logged out successfully'});
};

exports.sendVerificationCode = async (req, res) => {
    const { email } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res
                .status(404)
                .json({ success: false, message: 'User does not exist!' });
        }
        if (existingUser.verified) {
            return res
                .status(400)
                .json({ success: false, message: 'User is already verified' });
        }
        const codeValue = Math.floor(100000 + Math.random() * 1000000).toString();
        let info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: 'verification code',
            html: '<h1>' + codeValue + '</h1>'
        })

        if(info.accepted[0] === existingUser.email){
            const hashedCodeValue = hmacProcess(codeValue, process.env.
            HMAC_VERIFICATION_CODE_SECRET);
            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now();
            await existingUser.save();
            return res.status(200).json({
                success: true,
                message: 'Verification code has been sent to your email',
            });
        }
        res.status(400).json({ success: false, message: 'Code sent failed' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
}

exports.verifyVerificationCode = async (req, res) => {
    const {email, providedCode} = req.body;
    try {
        const {error} = acceptedCodeSchema.validate({email, providedCode});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        const codeValue = providedCode.toString();
        const existingUser = await
        User.findOne({email}).select('+verificationCode +verificationCodeValidation');
        if(!existingUser){
            return res
                .status(404)
                .json({success: false, message: 'User does not exist!'});
        }
        if(existingUser.verified){
            return res
                .status(400)
                .json({success: false, message: 'User is already verified'});
        }
        if(!existingUser.verificationCode || !existingUser.verificationCodeValidation){
            return res
                .status(400)
                .json({success: false, message: 'No verification code found'});
        }

        if(Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000){
            return res
                .status(400)
                .json({success: false, message: 'Verification code has expired'});
        }
        const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
        if(hashedCodeValue === existingUser.verificationCode){
            existingUser.verified = true;
            existingUser.verificationCode = undefined;
            existingUser.verificationCodeValidation = undefined;
            await existingUser.save();
            return res
                .status(200)
                .json({success: true, message: 'User has been verified'});
            return res
                .status(400)
                .json({success: false, message: 'Invalid verification code'});
        }
        return res
            .status(400)
            .json({success: false, message: 'Unexpected operation occurred!'});

    } catch (error) {
        console.log(error);
    }
}
