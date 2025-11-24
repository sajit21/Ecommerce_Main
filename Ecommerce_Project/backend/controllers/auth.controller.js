import { redis } from "../lib/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

const generateTokens = (userId) => {
	const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
		expiresIn: "15m",
	});

	const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
		expiresIn: "7d",
	});

	return { accessToken, refreshToken };
};

const storeRefreshToken = async (userId, refreshToken) => {
	await redis.set(`refresh_token:${userId}`, refreshToken, "EX", 7 * 24 * 60 * 60); // 7days
};

const setCookies = (res, accessToken, refreshToken) => {
	res.cookie("accessToken", accessToken, {
		httpOnly: true, // prevent XSS attacks, cross site scripting attack
		secure: process.env.NODE_ENV === "production",
		sameSite: "strict", // prevents CSRF attack, cross-site request forgery attack
		maxAge: 15 * 60 * 1000, // 15 minutes
	});
	res.cookie("refreshToken", refreshToken, {
		httpOnly: true, // prevent XSS attacks, cross site scripting attack
		secure: process.env.NODE_ENV === "production",
		sameSite: "strict", // prevents CSRF attack, cross-site request forgery attack
		maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
	});
};

export const signup = async (req, res) => {
	const { email, password, username } = req.body;
	console.log(email,password,username)
	try {
		const userExists = await User.findOne({ email });

		if (userExists) {
			return res.status(400).json({ error: "user already exists" });
		}
		const user = await User.create({ username, email, password });

		// authenticate
		const { accessToken, refreshToken } = generateTokens(user._id);
		await storeRefreshToken(user._id, refreshToken);

		setCookies(res, accessToken, refreshToken);

		res.status(201).json({
			_id: user._id,
			name: user.username,
			email: user.email,
			role: user.role,
		});
	} catch (error) {
		console.log("Error in signup controller", error.message);
		console.log("error hererer")
		res.status(500).json({ message: error.message });
	}
};

export const login = async (req, res) => {
	try {

		const { email, password } = req.body;
		console.log(email,password)
		const user = await User.findOne({ email });

		if (user && (await user.comparePassword(password))) {
			const { accessToken, refreshToken } = generateTokens(user._id);
			await storeRefreshToken(user._id, refreshToken);
			setCookies(res, accessToken, refreshToken);

			console.log('i am here')

			res.json({
				_id: user._id,
				name: user.name,
				email: user.email,
		
    		role: user.role,
			});
			
		} else {
			res.status(400).json({ message: "Invalid email or password" });
		}
	} catch (error) {
		console.log("Error in login controller", error.message);
		res.status(500).json({ message: error.message });
	}
   



    
};

export const logout = async (req, res) => {
	try {
		const refreshToken = req.cookies.refreshToken;
		if (refreshToken) {
			const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
			await redis.del(`refresh_token:${decoded.userId}`);
		}

		res.clearCookie("accessToken");
		res.clearCookie("refreshToken");
		res.json({ message: "Logged out successfully" });
	} catch (error) {
		console.log("Error in logout controller", error.message);
		res.status(500).json({ message: "Server error", error: error.message });
	}
};


export const refreshToken= async(req, res) =>{


    try {
        const refreshToken=req.cookies.refreshToken;


        if(!refreshToken)
        {

           return  res.status(401).json({success:fail , message:"token not found"})
        }

        //incase of yes token
        const decoded=jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET) //check the token signature from browser with secret key placed at env.
        const storeRefreshToken= await redis.get(`refresh_token:${decoded.userId}`) //is the refresh token saved in the redis is same as the token in the browser?

        //store bhako refresh token sanga match huncha ki nai
        if(storeRefreshToken !== refreshToken)
            {
            return res.status(401).json({message:"invalid refresh token"})
        }

        const accessToken=jwt.sign({userId: decoded.userId}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: "15min"});

        res.cookie("accessToken" ,accessToken ,{
            httpOnly :true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 15 * 60 *1000,

        })

        res.json({message: "token refreshed"});

        
    } catch (error) {
        console.log("error in refreshToken controller", error.message)
      res.status(500).json({message: "server error ", error:error.message });        
    }     
}
// this will refresh the access token
// export const refreshToken = async (req, res) => {
// 	try {
// 		const refreshToken = req.cookies.refreshToken;

// 		if (!refreshToken) {
// 			return res.status(401).json({ message: "No refresh token provided" });
// 		}

// 		const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
// 		const storedToken = await redis.get(`refresh_token:${decoded.userId}`);

// 		if (storedToken !== refreshToken) {
// 			return res.status(401).json({ message: "Invalid refresh token" });
// 		}

// 		const accessToken = jwt.sign({ userId: decoded.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

// 		res.cookie("accessToken", accessToken, {
// 			httpOnly: true,
// 			secure: process.env.NODE_ENV === "production",
// 			sameSite: "strict",
// 			maxAge: 15 * 60 * 1000,
// 		});

// 		res.json({ message: "Token refreshed successfully" });
// 	} catch (error) {
// 		console.log("Error in refreshToken controller", error.message);
// 		res.status(500).json({ message: "Server error", error: error.message });
// 	}
// };

export const getProfile = async (req, res) => {
	try {
		res.json(req.user);
	} catch (error) {
		res.status(500).json({ message: "Server error", error: error.message });
	}
};

// accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NzZkMDRkMjU4NjI1ODQ2ZDcyZmM2N2UiLCJpYXQiOjE3MzUyOTM2MjAsImV4cCI6MTczNTI5NDUyMH0.O4ZBRQYaVpwDjFYkF3l482faaXqjUjr-N6I7FoIYs3s; Path=/; HttpOnly; Expires=Fri, 27 Dec 2024 10:15:20 GMT;
// accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NzZkMDRkMjU4NjI1ODQ2ZDcyZmM2N2UiLCJpYXQiOjE3MzUyOTM2MjAsImV4cCI6MTczNTI5NDUyMH0.O4ZBRQYaVpwDjFYkF3l482faaXqjUjr-N6I7FoIYs3s; Path=/; HttpOnly; Expires=Fri, 27 Dec 2024 10:15:20 GMT;
// accessToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NzZkMDRkMjU4NjI1ODQ2ZDcyZmM2N2UiLCJpYXQiOjE3MzUyOTM4MzIsImV4cCI6MTczNTI5NDczMn0.QGIvux4IHlyzCJn35Ix4Cr-SqSkI7lmqgWWX9rInGRQ; Path=/; HttpOnly; Expires=Fri, 27 Dec 2024 10:18:52 GMT;
