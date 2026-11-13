const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Temporary storage for OTPs (Email -> OTP)
const otpStorage = {};

// 1. Send OTP Route
app.post('/api/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, message: 'Email zaroori hai!' });
    }

    // 6-digit random OTP generate karein
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStorage[email] = otp;

    const BREVO_API_KEY = process.env.BREVO_API_KEY;

    try {
        // Brevo API ko request bhejein email bhejne ke liye
        const response = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'api-key': BREVO_API_KEY,
                'content-type': 'application/json'
            },
            body: JSON.stringify({
                sender: { email: email, name: "Dice Game" }, // Aap yahan apna verified sender email daal sakte hain
                to: [{ email: email }],
                subject: "Aapka Game Login OTP",
                htmlContent: `<p>Aapka OTP code hai: <strong>${otp}</strong></p>`
            })
        });

        const data = await response.json();

        if (response.ok) {
            res.json({ success: true, message: 'OTP successfully bhej diya gaya hai!' });
        } else {
            console.error('Brevo Error:', data);
            res.status(400).json({ success: false, message: data.message || 'OTP bhejne me error aaya.' });
        }
    } catch (error) {
        console.error('Server Error:', error);
        res.status(500).json({ success: false, message: 'Server error ho gaya.' });
    }
});

// 2. Verify OTP Route
app.post('/api/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    
    if (otpStorage[email] && otpStorage[email] === otp) {
        delete otpStorage[email]; // Use hone ke baad OTP hata dein
        res.json({ success: true, message: 'OTP verified successfully!' });
    } else {
        res.status(400).json({ success: false, message: 'Galat OTP hai, dobara koshish karein.' });
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
