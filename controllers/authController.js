const jwt = require('jsonwebtoken');
const {
    signupSchema,
    signinSchema,
    acceptCodeSchema,
    changePasswordSchema
} = require('../middlewares/validator');
const User = require('../models/usersModel');
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing');
const transport = require('../middlewares/sendMail');

exports.signup = async (req, res) => {
    const { email, password } = req.body;
    try {
        const { error } = signupSchema.validate({ email, password });

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
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};

exports.signin = async (req, res) => {
    const { email, password } = req.body;
    try {
        const { error } = signinSchema.validate({ email, password });
        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }
        const existingUser = await User.findOne({ email }).select('+password');
        if (!existingUser) {
            return res.status(401).json({ success: false, message: 'User does not exist!' });
        }
        const result = await doHashValidation(password, existingUser.password);
        if (!result) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({
            userId: existingUser._id,
            email: existingUser.email,
            verified: existingUser.verified
        }, process.env.TOKEN_SECRET, { expiresIn: '8h' });
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
};

exports.signout = async (req, res) => {
    res
        .clearCookie('Authorization')
        .status(200)
        .json({ success: true, message: 'Logged out successfully' });
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
            subject: 'Verification code',
            html: '<h1>' + codeValue + '</h1>'
        });

        if (info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
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
};

exports.verifyVerificationCode = async (req, res) => {
    const { email, providedCode } = req.body;
    try {
        console.log('Request received:', { email, providedCode });

        const { error } = acceptCodeSchema.validate({ email, providedCode });
        if (error) {
            console.log('Validation error:', error.details[0].message);
            return res.status(401).json({ success: false, message: error.details[0].message });
        }

        const codeValue = providedCode.toString();
        console.log('Code value:', codeValue);

        const existingUser = await User.findOne({ email }).select('+verificationCode +verificationCodeValidation');
        if (!existingUser) {
            console.log('User does not exist:', email);
            return res.status(404).json({ success: false, message: 'User does not exist!' });
        }

        if (existingUser.verified) {
            console.log('User is already verified:', email);
            return res.status(400).json({ success: false, message: 'User is already verified' });
        }

        if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
            console.log('No verification code found for user:', email);
            return res.status(400).json({ success: false, message: 'No verification code found' });
        }

        if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
            console.log('Verification code has expired for user:', email);
            return res.status(400).json({ success: false, message: 'Verification code has expired' });
        }

        const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
        console.log('Hashed code value:', hashedCodeValue);

        if (hashedCodeValue === existingUser.verificationCode) {
            existingUser.verified = true;
            existingUser.verificationCode = undefined;
            existingUser.verificationCodeValidation = undefined;
            await existingUser.save();
            console.log('User has been verified:', email);
            return res.status(200).json({ success: true, message: 'User has been verified' });
        }

        console.log('Invalid verification code for user:', email);
        return res.status(400).json({ success: false, message: 'Invalid verification code' });
    } catch (error) {
        console.log('Internal Server Error:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};

exports.changePassword = async (req, res) => {
    const { userId, verified } = req.user;
    const { oldPassword, newPassword } = req.body;
    try {
        const { error } = changePasswordSchema.validate({ oldPassword, newPassword });
        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }
        if (!verified) {
            return res
                .status(401)
                .json({ success: false, message: 'User is not verified' });
        }
        const existingUser = await User.findById(userId).select('+password');
        if (!existingUser) {
            return res
                .status(401)
                .json({ success: false, message: 'User does not exist!' });
        }
        const result = await doHashValidation(oldPassword, existingUser.password);
        if (!result) {
            return res
                .status(401)
                .json({ success: false, message: 'Invalid credentials' });
        }
        const hashedPassword = await doHash(newPassword, 12);
        existingUser.password = hashedPassword;
        await existingUser.save();
        return res
            .status(200)
            .json({ success: true, message: 'Password has been updated successfully' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
};