const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());

const users = [
	{
		id: "1",
		username: "john",
		password: "John0908",
		isAdmin: true,
	},
	{
		id: "2",
		username: "jane",
		password: "Jane0908",
		isAdmin: false,
	},
];

let refreshTokens = [];
app.post("/api/refresh", (req, res) => {
	//take the refresh token from user
	const refreshToken = req.body.token;
	// send error if ther is no token or it's invalid
	if (!refreshToken) return res.status(401).json("you are not authenticated");
	if (!refreshToken.includes(refreshToken))
		return res.status(403).json("refresh token is not valid");

	jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
		err && console.log(err);
		refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
		const newAccessToken = generateAccessToken(user);
		const newRefreshToken = generateRefreshToken(user);

		refreshTokens.push(newRefreshToken);
		res.status(200).json({
			accessToken: newAccessToken,
			refreshToken: newRefreshToken,
		});
	});
	//if every thinf is ok ,create new access token,refresh token and send to user
});

const generateAccessToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
		expiresIn: "15m",
	});
};

const generateRefreshToken = (user) => {
	return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretKey");
};
app.post("/api/login", (req, res) => {
	const { username, password } = req.body;
	const user = users.find((u) => {
		return u.username == username && u.password == password;
	});

	if (user) {
		// generate access token
		const accessToken = generateAccessToken(user);
		const refreshToken = generateRefreshToken(user);
		refreshTokens.push(refreshToken);

		res.json({
			username: user.username,
			isAdmin: user.isAdmin,
			accessToken,
			refreshToken,
		});
	} else {
		res.status(400).json("username or password incorrect");
	}
});

const verify = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.split(" ")[1];

		jwt.verify(token, "mySecretKey", (err, user) => {
			if (err) {
				return res.status(403).json("token is not valid");
			} else {
				req.user = user;
				next();
			}
		});
	} else {
		res.status(401).json("you are not authenticated");
	}
};

app.delete("/api/users/:userId", verify, (req, res) => {
	if (req.user.id === req.params.userId || req.user.isAdmin) {
		res.status(200).json("user has been deleted");
	} else {
		res.status(403).json("you are not allowed to delete this user ");
	}
});

app.post("/api/logout", verify, (req, res) => {
	const refreshToken = req.body.token;
	refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
	res.status(200).json("you logged out successfuly");
});
app.listen(5000, () => {
	console.log("backend server is running");
});
