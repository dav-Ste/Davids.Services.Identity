using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Davids.Services.Identity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddCustomerChangeAudits : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CustomerChangeAuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    TargetUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TargetEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    Action = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ActorSub = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ActorEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: true),
                    ActorRole = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ActorAuthority = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ChangedFieldsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CorrelationId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CustomerChangeAuditLogs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CustomerChangeAuditLogs_ActorSub_OccurredAtUtc",
                table: "CustomerChangeAuditLogs",
                columns: new[] { "ActorSub", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CustomerChangeAuditLogs_OccurredAtUtc",
                table: "CustomerChangeAuditLogs",
                column: "OccurredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CustomerChangeAuditLogs_TargetUserId_OccurredAtUtc",
                table: "CustomerChangeAuditLogs",
                columns: new[] { "TargetUserId", "OccurredAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CustomerChangeAuditLogs");
        }
    }
}
