// AuthController.cs

using Microsoft.AspNetCore.Mvc;
using firstAPIs.Models;
using firstAPIs.Services;

namespace firstAPIs.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var (success, message, user) = await _authService.RegisterAsync(request);
        
        if (!success)
            return BadRequest(new { message });
        
        _logger.LogInformation($"New user registered: {user?.Email}");
        return Ok(new { message, user = new { user?.Id, user?.Email, user?.Name } });
    }
    
    [HttpPost("send-otp")]
    public async Task<IActionResult> SendOtp([FromBody] OtpRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var (success, message) = await _authService.SendOtpAsync(request);
        
        if (!success)
            return BadRequest(new { message });
        
        return Ok(new { message });
    }
    
    [HttpPost("verify-otp")]
    public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var (success, message) = await _authService.VerifyOtpAsync(request);
        
        if (!success)
            return BadRequest(new { message });
        
        return Ok(new { message });
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var (success, message, token, user) = await _authService.LoginAsync(request);
        
        if (!success)
            return Unauthorized(new { message });
        
        return Ok(new AuthResponse { Token = token!, User = user! });
    }
    
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var (success, message) = await _authService.ForgotPasswordAsync(request);
        
        if (!success)
            return BadRequest(new { message });
        
        return Ok(new { message });
    }
    
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        
        var (success, message) = await _authService.ResetPasswordAsync(request);
        
        if (!success)
            return BadRequest(new { message });
        
        return Ok(new { message });
    }
}