using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using firstAPIs.Data;
using firstAPIs.Models;

namespace firstAPIs.Controllers;

[ApiController]
[Route("api/user")]
[Authorize] // This protects ALL routes in this controller by default
public class UserController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly ILogger<UserController> _logger;
    
    public UserController(AppDbContext context, ILogger<UserController> logger)
    {
        _context = context;
        _logger = logger;
    }
    
    // GET: api/user/me
    // Gets the currently logged-in user's information
    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        // Get user ID from the JWT token (automatically validated by .NET)
        var userIdClaim = User.FindFirst("id")?.Value;
        
        if (string.IsNullOrEmpty(userIdClaim))
        {
            return Unauthorized(new { message = "User not found in token" });
        }
        
        var userId = int.Parse(userIdClaim);
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
        {
            return NotFound(new { message = "User not found" });
        }
        
        return Ok(new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            Name = user.Name,
            CreatedAt = user.CreatedAt
        });
    }
    

    // GET: api/user/all
    // Admin only - gets all users
    [HttpGet("all")]
    [Authorize(Roles = "Admin")] // Override - only admins can access this
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users
            .Select(u => new UserDto
            {
                Id = u.Id,
                Email = u.Email,
                Name = u.Name,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
        
        _logger.LogInformation($"Admin retrieved all users. Total: {users.Count}");
        return Ok(users);
    }
    

    // GET: api/user/admins
    // Admin only - gets all admin users
    [HttpGet("admins")]
    [Authorize(Roles = "Admin")]
    
    public async Task<IActionResult> GetAllAdmins()
    {
        // This assumes you have a Role property in your User model
        // If not, you'll need to add it to the User model first
        var admins = await _context.Users
            .Where(u => u.Role == "Admin") // You'll need to add Role to User model
            .Select(u => new UserDto
            {
                Id = u.Id,
                Email = u.Email,
                Name = u.Name,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
        
        return Ok(admins);
    }
}