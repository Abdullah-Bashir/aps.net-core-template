using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using firstAPIs.Data;
using firstAPIs.Models;

namespace firstAPIs.Controllers;

[ApiController]
[Route("api/user")]
[Authorize]
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
    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
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
            IsEmailVerified = user.IsEmailVerified,
            CreatedAt = user.CreatedAt
        });
    }
    
    // GET: api/user/all
    [HttpGet("all")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _context.Users
            .Select(u => new UserDto
            {
                Id = u.Id,
                Email = u.Email,
                Name = u.Name,
                IsEmailVerified = u.IsEmailVerified,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
        
        _logger.LogInformation($"Admin retrieved all users. Total: {users.Count}");
        return Ok(users);
    }
    
    // GET: api/user/admins
    [HttpGet("admins")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetAllAdmins()
    {
        var admins = await _context.Users
            .Where(u => u.Role == "Admin")
            .Select(u => new UserDto
            {
                Id = u.Id,
                Email = u.Email,
                Name = u.Name,
                IsEmailVerified = u.IsEmailVerified,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
        
        return Ok(admins);
    }
    
    // GET: api/user/verified
    [HttpGet("verified")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetVerifiedUsers()
    {
        var verifiedUsers = await _context.Users
            .Where(u => u.IsEmailVerified == true)
            .Select(u => new UserDto
            {
                Id = u.Id,
                Email = u.Email,
                Name = u.Name,
                IsEmailVerified = u.IsEmailVerified,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
        
        return Ok(verifiedUsers);
    }
    
    // GET: api/user/unverified
    [HttpGet("unverified")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetUnverifiedUsers()
    {
        var unverifiedUsers = await _context.Users
            .Where(u => u.IsEmailVerified == false)
            .Select(u => new UserDto
            {
                Id = u.Id,
                Email = u.Email,
                Name = u.Name,
                IsEmailVerified = u.IsEmailVerified,
                CreatedAt = u.CreatedAt
            })
            .ToListAsync();
        
        return Ok(unverifiedUsers);
    }
}