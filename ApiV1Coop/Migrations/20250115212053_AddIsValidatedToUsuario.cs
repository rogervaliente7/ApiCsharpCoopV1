using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ApiV1Coop.Migrations
{
    /// <inheritdoc />
    public partial class AddIsValidatedToUsuario : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "is_validated",
                table: "Usuarios",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "is_validated",
                table: "Usuarios");
        }
    }
}
