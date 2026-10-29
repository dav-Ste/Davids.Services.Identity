# Build from workspace parent directory so sibling ../Davids.Shared is in build context:
#   docker build -f Davids.Services.Identity/Dockerfile -t ghcr.io/davids/davids-services-identity:1.0.0 .
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build
WORKDIR /workspace

COPY Davids.Shared/Directory.Build.props Davids.Shared/Directory.Packages.props Davids.Shared/global.json ./Davids.Shared/
COPY Davids.Shared/eng/ ./Davids.Shared/eng/
COPY Davids.Shared/src/Davids.ServiceDefaults/Davids.ServiceDefaults.csproj Davids.Shared/src/Davids.ServiceDefaults/packages.lock.json ./Davids.Shared/src/Davids.ServiceDefaults/
COPY Davids.Services.Identity/Directory.Build.props Davids.Services.Identity/Directory.Packages.props Davids.Services.Identity/global.json ./Davids.Services.Identity/
COPY Davids.Services.Identity/src/Davids.Services.Identity.Core/Davids.Services.Identity.Core.csproj Davids.Services.Identity/src/Davids.Services.Identity.Core/packages.lock.json ./Davids.Services.Identity/src/Davids.Services.Identity.Core/
COPY Davids.Services.Identity/src/Davids.Services.Identity.Application/Davids.Services.Identity.Application.csproj Davids.Services.Identity/src/Davids.Services.Identity.Application/packages.lock.json ./Davids.Services.Identity/src/Davids.Services.Identity.Application/
COPY Davids.Services.Identity/src/Davids.Services.Identity.Infrastructure/Davids.Services.Identity.Infrastructure.csproj Davids.Services.Identity/src/Davids.Services.Identity.Infrastructure/packages.lock.json ./Davids.Services.Identity/src/Davids.Services.Identity.Infrastructure/
COPY Davids.Services.Identity/src/Davids.Services.Identity.Api/Davids.Services.Identity.Api.csproj Davids.Services.Identity/src/Davids.Services.Identity.Api/packages.lock.json ./Davids.Services.Identity/src/Davids.Services.Identity.Api/

RUN dotnet restore ./Davids.Services.Identity/src/Davids.Services.Identity.Api/Davids.Services.Identity.Api.csproj --locked-mode

COPY Davids.Shared/src/Davids.ServiceDefaults/ ./Davids.Shared/src/Davids.ServiceDefaults/
COPY Davids.Services.Identity/src/ ./Davids.Services.Identity/src/

RUN dotnet publish ./Davids.Services.Identity/src/Davids.Services.Identity.Api/Davids.Services.Identity.Api.csproj \
      --no-restore -c Release /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS runtime
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build --chown=10001:10001 /workspace/Davids.Services.Identity/artifacts/publish/Davids.Services.Identity.Api/release .
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["dotnet", "--info"]

ENTRYPOINT ["dotnet", "Davids.Services.Identity.Api.dll"]
