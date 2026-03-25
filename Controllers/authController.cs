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
    
    // POST: api/auth/register
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var (success, message, user) = await _authService.RegisterAsync(request);
        
        if (!success)
        {
            return BadRequest(new { message });
        }
        
        _logger.LogInformation($"New user registered: {user?.Email}");
        return Ok(new { message, user = new { user?.Id, user?.Email, user?.Name } });
    }
    
    // POST: api/auth/login
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var (success, message, token, user) = await _authService.LoginAsync(request);
        
        if (!success)
        {
            return Unauthorized(new { message });
        }
        
        return Ok(new AuthResponse
        {
            Token = token!,
            User = user!
        });
    }
    
    // Validate-token route REMOVED - .NET handles this automatically!
}