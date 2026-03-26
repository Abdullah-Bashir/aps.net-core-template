// AuthService.cs

using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using firstAPIs.Models;
using firstAPIs.Data;
using System.Security.Cryptography;
using System.Net.Mail;
using System.Net;

namespace firstAPIs.Services;

public interface IAuthService
{
    Task<(bool Success, string Message, User? User)> RegisterAsync(RegisterRequest request);
    Task<(bool Success, string Message, string? Token, UserDto? User)> LoginAsync(LoginRequest request);
    Task<(bool Success, string Message)> SendOtpAsync(OtpRequest request);
    Task<(bool Success, string Message)> VerifyOtpAsync(VerifyOtpRequest request);
    Task<(bool Success, string Message)> ForgotPasswordAsync(ForgotPasswordRequest request);
    Task<(bool Success, string Message)> ResetPasswordAsync(ResetPasswordRequest request);
}

public class AuthService : IAuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthService> _logger;

    public AuthService(AppDbContext context, IConfiguration configuration, ILogger<AuthService> logger)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<(bool Success, string Message, User? User)> RegisterAsync(RegisterRequest request)
    {
        var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (existingUser != null)
        {
            return (false, "User with this email already exists", null);
        }

        var otp = GenerateOtp();
        var otpExpiry = DateTime.UtcNow.AddMinutes(10);

        var user = new User
        {
            Email = request.Email,
            Name = request.Name,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            EmailVerificationToken = otp,
            EmailVerificationTokenExpiry = otpExpiry,
            IsEmailVerified = false,
            CreatedAt = DateTime.UtcNow,
            Role = !await _context.Users.AnyAsync() ? "Admin" : "User"
        };

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        // Send verification email with OTP
        await SendVerificationEmail(user.Email, user.Name, otp);

        return (true, "Registration successful. Please check your email for OTP verification.", user);
    }

    public async Task<(bool Success, string Message, string? Token, UserDto? User)> LoginAsync(LoginRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
        {
            return (false, "Invalid email or password", null, null);
        }

        if (!user.IsEmailVerified)
        {
            return (false, "Please verify your email first. Check your inbox for OTP.", null, null);
        }

        if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            return (false, "Invalid email or password", null, null);
        }

        var token = GenerateJwtToken(user);

        var userDto = new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            Name = user.Name,
            IsEmailVerified = user.IsEmailVerified,
            CreatedAt = user.CreatedAt
        };

        return (true, "Login successful", token, userDto);
    }

    public async Task<(bool Success, string Message)> SendOtpAsync(OtpRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
        {
            return (false, "User not found");
        }

        var otp = GenerateOtp();
        var otpExpiry = DateTime.UtcNow.AddMinutes(10);

        user.EmailVerificationToken = otp;
        user.EmailVerificationTokenExpiry = otpExpiry;

        await _context.SaveChangesAsync();

        await SendVerificationEmail(user.Email, user.Name, otp);

        return (true, $"Verification OTP sent to {user.Email}. Valid for 10 minutes.");
    }

    public async Task<(bool Success, string Message)> VerifyOtpAsync(VerifyOtpRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
        {
            return (false, "User not found");
        }

        if (user.EmailVerificationToken == null || user.EmailVerificationTokenExpiry == null)
        {
            return (false, "No OTP found. Request a new OTP.");
        }

        if (user.EmailVerificationTokenExpiry < DateTime.UtcNow)
        {
            return (false, "OTP has expired. Please request a new one.");
        }

        if (user.EmailVerificationToken != request.Otp)
        {
            return (false, "Invalid OTP");
        }

        user.IsEmailVerified = true;
        user.EmailVerificationToken = null;
        user.EmailVerificationTokenExpiry = null;

        await _context.SaveChangesAsync();

        return (true, "Email verified successfully. You can now login.");
    }

    public async Task<(bool Success, string Message)> ForgotPasswordAsync(ForgotPasswordRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
        if (user == null)
        {
            // Security: Don't reveal if user exists
            return (true, "If your email is registered, you will receive a password reset link.");
        }

        // Generate a random token
        var resetToken = GenerateRandomToken();

        // Hash the token for storage (like Express crypto.createHash)
        var hashedToken = HashToken(resetToken);

        user.PasswordResetToken = hashedToken;
        user.PasswordResetTokenExpiry = DateTime.UtcNow.AddMinutes(10);

        await _context.SaveChangesAsync();

        // Create reset link
        var frontendUrl = _configuration["FrontendUrl"] ?? "http://localhost:3000";
        var resetUrl = $"{frontendUrl}/reset-password/{resetToken}";

        // Send email with reset link
        await SendPasswordResetEmail(user.Email, user.Name, resetUrl);

        return (true, "If your email is registered, you will receive a password reset link.");
    }

    public async Task<(bool Success, string Message)> ResetPasswordAsync(ResetPasswordRequest request)
    {
        if (request.NewPassword != request.ConfirmPassword)
        {
            return (false, "Passwords do not match");
        }

        // Hash the token from request to compare with stored hash
        var hashedToken = HashToken(request.Token);

        var user = await _context.Users.FirstOrDefaultAsync(u =>
            u.PasswordResetToken == hashedToken &&
            u.PasswordResetTokenExpiry > DateTime.UtcNow);

        if (user == null)
        {
            return (false, "Invalid or expired reset token");
        }

        // Update password
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
        user.PasswordResetToken = null;
        user.PasswordResetTokenExpiry = null;

        await _context.SaveChangesAsync();

        return (true, "Password reset successfully. You can now login with your new password.");
    }

    // ==================== EMAIL SENDING METHODS (Gmail SMTP) ====================

    private async Task SendVerificationEmail(string email, string name, string otp)
    {
        var htmlBody = $@"
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;'>
                <h2 style='color: #333;'>Welcome to {_configuration["AppName"] ?? "Our App"}!</h2>
                <p style='font-size: 16px; color: #555;'>Hi {name},</p>
                <p style='font-size: 16px; color: #555;'>Thank you for registering. Please verify your email using the code below:</p>
                <div style='background-color: #f5f5f5; padding: 15px; text-align: center; border-radius: 5px; margin: 20px 0;'>
                    <h1 style='font-size: 32px; letter-spacing: 5px; color: #007bff;'>{otp}</h1>
                </div>
                <p style='font-size: 14px; color: #777;'>This code expires in 10 minutes.</p>
                <p style='font-size: 14px; color: #777;'>If you didn't request this, please ignore this email.</p>
                <hr style='margin: 20px 0;' />
                <p style='font-size: 12px; color: #999;'>&copy; {DateTime.Now.Year} {_configuration["AppName"] ?? "Our App"}. All rights reserved.</p>
            </div>
        ";

        await SendEmail(email, "Verify Your Email Address", htmlBody);
    }

    private async Task SendPasswordResetEmail(string email, string name, string resetUrl)
    {
        var htmlBody = $@"
            <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;'>
                <h2 style='color: #333;'>Password Reset Request</h2>
                <p style='font-size: 16px; color: #555;'>Hi {name},</p>
                <p style='font-size: 16px; color: #555;'>We received a request to reset your password. Click the button below to reset it:</p>
                <div style='text-align: center; margin: 30px 0;'>
                    <a href='{resetUrl}' style='background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Reset Password</a>
                </div>
                <p style='font-size: 14px; color: #777;'>Or copy this link: <br/>{resetUrl}</p>
                <p style='font-size: 14px; color: #777;'>This link expires in 10 minutes.</p>
                <p style='font-size: 14px; color: #777;'>If you didn't request this, please ignore this email.</p>
                <hr style='margin: 20px 0;' />
                <p style='font-size: 12px; color: #999;'>&copy; {DateTime.Now.Year} {_configuration["AppName"] ?? "Our App"}. All rights reserved.</p>
            </div>
        ";

        await SendEmail(email, "Password Reset Request", htmlBody);
    }

    private async Task SendEmail(string to, string subject, string htmlBody)
    {
        try
        {
            var smtpSettings = _configuration.GetSection("Smtp");
            var useRealEmail = smtpSettings.GetValue<bool>("UseRealEmail");
            var emailUser = smtpSettings["Email"];
            var emailPass = smtpSettings["Password"];

            if (useRealEmail && !string.IsNullOrEmpty(emailUser) && !string.IsNullOrEmpty(emailPass))
            {
                // Send real email via Gmail SMTP
                using var client = new SmtpClient(smtpSettings["Host"], smtpSettings.GetValue<int>("Port"));
                client.EnableSsl = smtpSettings.GetValue<bool>("EnableSsl");
                client.Credentials = new NetworkCredential(emailUser, emailPass);

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(emailUser, _configuration["AppName"] ?? "Our App"),
                    Subject = subject,
                    Body = htmlBody,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(to);

                await client.SendMailAsync(mailMessage);
                _logger.LogInformation($"Email sent to {to}: {subject}");
            }
            else
            {
                // Development mode - log email
                _logger.LogInformation($"[EMAIL SIMULATION] To: {to}, Subject: {subject}");
                _logger.LogInformation($"[EMAIL SIMULATION] Body: {htmlBody}");

                // Save to file for testing
                var emailLog = $@"
=== EMAIL {DateTime.Now} ===
To: {to}
Subject: {subject}
Body: {htmlBody}
----------------------------------------
";
                await System.IO.File.AppendAllTextAsync("email_logs.txt", emailLog);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Failed to send email to {to}");
            // Don't throw - email failure shouldn't break auth flow
        }
    }

    // ==================== HELPER METHODS ====================

    private string GenerateOtp()
    {
        Random random = new Random();
        return random.Next(100000, 999999).ToString();
    }

    private string GenerateRandomToken()
    {
        // Generate 40 character random token (like crypto.randomBytes in Node)
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(20)).ToLower();
    }

    private string HashToken(string token)
    {
        // Hash token for storage (like crypto.createHash in Node)
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash).ToLower();
    }

    private string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured"));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("id", user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("IsEmailVerified", user.IsEmailVerified.ToString())
            }),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}