using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ApiV1Coop.Migrations
{
    /// <inheritdoc />
    public partial class AddOptCodeToUsuario : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "opt_code",
                table: "Usuarios",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "opt_code",
                table: "Usuarios");
        }
    }
}
