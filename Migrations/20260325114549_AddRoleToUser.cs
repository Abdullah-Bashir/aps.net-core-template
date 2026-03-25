using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace firstAPIs.Migrations
{
    /// <inheritdoc />
    public partial class AddRoleToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // ONLY add the Role column to the existing Users table
            migrationBuilder.AddColumn<string>(
                name: "Role",
                table: "Users",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "User");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Remove the Role column if we rollback
            migrationBuilder.DropColumn(
                name: "Role",
                table: "Users");
        }
    }
}