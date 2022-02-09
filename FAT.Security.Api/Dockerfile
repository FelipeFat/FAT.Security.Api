#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["FAT.Security.Api/FAT.Security.Api.csproj", "FAT.Security.Api/"]
RUN dotnet restore "FAT.Security.Api/FAT.Security.Api.csproj"
COPY . .
WORKDIR "/src/FAT.Security.Api"
RUN dotnet build "FAT.Security.Api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "FAT.Security.Api.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "FAT.Security.Api.dll"]