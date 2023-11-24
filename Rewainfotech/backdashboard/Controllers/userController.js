
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../models')
const User = db.user;

const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, 'secret', { expiresIn: '5d' });
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: Missing token' });
    }

    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized: Invalid token' });
        }
        req.userId = decoded.userId;
        next();
    });
};


const userCtrl = {
    postUsers: async (req, res) => {
        try {
            const { email, password, phone, firstName, lastName } = req.body;
            const hashedPassword = await bcrypt.hash(password, 10);
            const userData = {
                email,
                phone,
                firstName,
                lastName,
                password: hashedPassword,
            };
            const user = await User.create(userData);
            const accessToken = generateAccessToken(user.id);
            const responseData = {
                id: user.id,
                email: user.email,
                phone: user.phone,
                firstName: user.firstName,
                lastName: user.lastName,
            };
            res.status(200).json({ status: 200, user: responseData, accessToken });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    },
    loginUser: async (req, res) => {
        const { email, password } = req.body;
        try {
            const user = await User.findOne({ where: { email } });

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            const isValidPassword = await bcrypt.compare(password, user.password);

            if (!isValidPassword) {
                return res.status(401).json({ message: 'Invalid password' });
            }
            const accessToken = generateAccessToken(user.id);
            const responseData = {
                id: user.id,
                email: user.email,
                phone: user.phone,
                firstName: user.firstName,
                lastName: user.lastName,
            };
            return res.status(200).json({ status: 200, message: 'Login successful', user: responseData, accessToken });
        } catch (error) {
            return res.status(500).json({ message: 'Server error' });
        }
    },
    updateUserProfile: async (req, res) => {
        try {
            const { id } = req.params;
            const updatedData = req.body;

            const [rowsUpdated] = await User.update(updatedData, {
                where: {
                    id
                }
            });
            if (rowsUpdated === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            return res.status(200).json({ status: 200, message: 'User profile updated successfully' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    },
    getUsers: async (req, res) => {
        try {
            const users = await User.findAll({});
            res.status(200).json({ status: 200, users });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    },
    getUser: async (req, res) => {
        try {
            const { id } = req.params;
            const user = await User.findOne({
                where: {
                    id
                }
            });
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.status(200).json({ status: 200, user });
        } catch (error) {
            // console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    },

    // var deleteUser = async (req, res) => {
    //     const data = await User.destroy({
    //         where: {
    //             id: req.params.id
    //         }
    //     })
    //     res.status(200).json({ data: data })
    // }

    // updateUser: async (req, res) => {
    //     try {
    //         const { id } = req.params;
    //         const updatedData = req.body;

    //         const [rowsUpdated] = await User.update(updatedData, {
    //             where: {
    //                 id
    //             }
    //         });
    //         if (rowsUpdated === 0) {
    //             return res.status(404).json({ error: 'User not found' });
    //         }
    //         res.status(200).json({ status: 200, message: 'User updated successfully' });
    //     } catch (error) {
    //         console.error(error);
    //         res.status(500).json({ error: 'Internal Server Error' });
    //     }
    // },
    updateUserPassword: async (req, res) => {
        try {
            const { id } = req.params;
            const { oldPassword, newPassword, confirmPassword } = req.body;
            const token = req.headers['authorization'];

            if (!token) {
                return res.status(401).json({ error: 'Unauthorized: Missing token' });
            }

            try {
                const decodedToken = jwt.verify(token.split(' ')[1], 'secret');
                const userIdFromToken = decodedToken.userId;

                if (userIdFromToken !== id) {
                    return res.status(401).json({ error: 'Unauthorized: Invalid token for this user' });
                }
            } catch (error) {
                return res.status(401).json({ error: 'Unauthorized: Invalid token' });
            }

            const user = await User.findByPk(id);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            const isPasswordValid = await user.comparePassword(oldPassword);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid old password' });
            }

            if (newPassword !== confirmPassword) {
                return res.status(400).json({ error: 'New password and confirm password do not match' });
            }

            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedNewPassword;
            await user.save();

            return res.status(200).json({ status: 200, message: 'User password updated successfully' });

        } catch (error) {
            console.error(error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
    }
    // updateUserPassword: async (req, res) => {
    //     try {
    //         const { id } = req.params;
    //         const { oldPassword, newPassword, confirmPassword } = req.body;
    //         const token = req.headers['authorization'];

    //         if (!token) {
    //             return res.status(401).json({ error: 'Unauthorized: Missing token' });
    //         }

    //         try {
    //             const decodedToken = jwt.verify(token.split(' ')[1], 'secret');
    //             const userIdFromToken = decodedToken.userId;

    //             if (userIdFromToken !== id) {
    //                 return res.status(401).json({ error: 'Unauthorized: Invalid token for this user' });
    //             }
    //         } catch (error) {
    //             return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    //         }

    //         const user = await User.findByPk(id);
    //         if (!user) {
    //             return res.status(404).json({ error: 'User not found' });
    //         }

    //         const isPasswordValid = await user.comparePassword(oldPassword);
    //         if (!isPasswordValid) {
    //             return res.status(401).json({ error: 'Invalid old password' });
    //         }

    //         if (newPassword !== confirmPassword) {
    //             return res.status(400).json({ error: 'New password and confirm password do not match' });
    //         }

    //         const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    //         user.password = hashedNewPassword;
    //         await user.save();

    //         return res.status(200).json({ status: 200, message: 'User password updated successfully' });

    //     } catch (error) {
    //         console.error(error);
    //         return res.status(500).json({ error: 'Internal Server Error' });
    //     }
    // }

    // updateUserPassword: async (req, res) => {
    //     try {
    //         const { id } = req.params;
    //         const { oldPassword, newPassword, confirmPassword } = req.body;
    //         const token = req.headers['authorization'];
    //         if (!token) {
    //             return res.status(401).json({ error: 'Unauthorized: Missing token' });
    //         }

    //         try {
    //             const decodedToken = jwt.verify(token.split(' ')[1], 'secret');
    //             const userIdFromToken = decodedToken.userId;

    //             if (userIdFromToken === id) {
    //                 return res.status(401).json({ error: 'Unauthorized: Invalid token for this user' });
    //             }
    //         } catch (error) {
    //             return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    //         }

    //         const user = await User.findByPk(id);
    //         if (!user) {
    //             return res.status(404).json({ error: 'User not found' });
    //         }
    //         const isPasswordValid = await user.comparePassword(oldPassword);
    //         if (!isPasswordValid) {
    //             return res.status(401).json({ error: 'Invalid old password' });
    //         }
    //         if (newPassword !== confirmPassword) {
    //             return res.status(400).json({ error: 'New password and confirm password do not match' });
    //         }
    //         const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    //         user.password = hashedNewPassword;
    //         await user.save();

    //         return res.status(200).json({ status: 200, message: 'User password updated successfully' });

    //     } catch (error) {
    //         console.error(error);
    //         res.status(500).json({ error: 'Internal Server Error' });
    //     }
    // }
};

module.exports = {
    userCtrl,
    authenticateToken,
}