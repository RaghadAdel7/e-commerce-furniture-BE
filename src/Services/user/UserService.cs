using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using src.Repository;
using src.Controllers;
using static src.DTO.UserDTO;
using src.Entity;
using src.Utils;
using static src.Entity.User;
using src.DTO;
using Microsoft.Extensions.Configuration;

namespace src.Services.user
{
    public class UserService : IUserService
    {
        protected readonly UserRepository _userRepo;
        protected readonly IMapper _mapper;
        protected readonly IConfiguration _config;

        public UserService(UserRepository userRepo, IMapper mapper, IConfiguration config)
        {
            _userRepo = userRepo;
            _mapper = mapper;
            _config = config;
        }

        public async Task<UserReadDto> CreateOneAsync(UserCreateDto createDto)
        {
            var user = _mapper.Map<UserCreateDto, User>(createDto);
            var userTable = await _userRepo.GetAllAsync();

            ValidateUser(user, userTable);

            user.Role = GetUserRole(user.Email);
            // user.CartId = Guid.NewGuid();

            HashPassword(createDto.Password, user);

            var savedUser = await _userRepo.CreateOneAsync(user);
            return _mapper.Map<User, UserReadDto>(savedUser);
        }

        private void ValidateUser(User user, List<User> userTable)
        {
            if (string.IsNullOrEmpty(user.Email))
                throw CustomException.BadRequest("You can't leave Email empty");
            if (userTable.Any(x => x.Email == user.Email))
                throw CustomException.BadRequest("Email already registered, please try another one");

            if (string.IsNullOrEmpty(user.PhoneNumber))
                throw CustomException.BadRequest("You can't leave phone number empty");
            if (userTable.Any(x => x.PhoneNumber == user.PhoneNumber))
                throw CustomException.BadRequest("Phone number already registered, please try another one");

            if (string.IsNullOrEmpty(user.Username))
                throw CustomException.BadRequest("You can't leave Username empty");
            if (userTable.Any(x => x.Username == user.Username))
                throw CustomException.BadRequest("Username already registered, please try another one");

            if (string.IsNullOrEmpty(user.FirstName))
                throw CustomException.BadRequest("You can't leave First name empty");
            if (string.IsNullOrEmpty(user.LastName))
                throw CustomException.BadRequest("You can't leave Last name empty");

            if (user.BirthDate.Equals(DateOnly.Parse("0001-01-01")))
                throw CustomException.BadRequest("You can't leave birthdate empty");

            ValidatePassword(user.Password);
        }

        private void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw CustomException.BadRequest("You can't leave Password empty");
            if (password.Length < 8)
                throw CustomException.BadRequest("Password should be at least 8 characters");
            if (!password.Any(char.IsDigit))
                throw CustomException.BadRequest("Password should contain at least one number");
            if (!password.Any(ch => "!@#$%^&*()_-[]".Contains(ch)))
                throw CustomException.BadRequest("Password should contain at least one special character (! - @ - # - $ - % - & - * - ( - ) - _ - [ - ])");
        }

        private UserRole GetUserRole(string email)
        {
            return email.Contains("@admin.com") ? UserRole.Admin : UserRole.Customer;
        }

        private void HashPassword(string password, User user)
        {
            PasswordUtils.HashPassword(password, out string hashedPassword, out byte[] salt);
            user.Password = hashedPassword;
            user.Salt = salt;
        }

        public async Task<string> SignInAsync(UserCreateDto createDto)
        {
            var foundUser = await _userRepo.FindByEmailAsync(createDto.Email);
            if (foundUser == null)
                throw CustomException.BadRequest("User not found.");

            if (!PasswordUtils.VerifyPassword(createDto.Password, foundUser.Password, foundUser.Salt))
                throw CustomException.UnAuthorized($"Password does not match for {foundUser.Email}");

            var tokenUtil = new TokenUtils(_config);
            return tokenUtil.GenerateToken(foundUser);
        }

        public async Task<UserReadDto> GetByIdAsync(Guid id)
        {
            var foundUser = await _userRepo.GetByIdAsync(id);
            return _mapper.Map<User, UserReadDto>(foundUser);
        }

        public async Task<bool> DeleteOneAsync(Guid id)
        {
            var foundUser = await _userRepo.GetByIdAsync(id);
            return await _userRepo.DeleteOneAsync(foundUser);
        }

        public async Task<bool> UpdateOneAsync(Guid id, UserUpdateDto updateDto)
        {
            var foundUser = await _userRepo.GetByIdAsync(id);
            if (foundUser == null)
                throw CustomException.BadRequest($"User with {id} doesn't exist");

            var userTable = await _userRepo.GetAllAsync();
            ValidateUpdateUser(updateDto, foundUser, userTable);

            _mapper.Map(updateDto, foundUser);
            return await _userRepo.UpdateOneAsync(foundUser);
        }

        private void ValidateUpdateUser(UserUpdateDto updateDto, User foundUser, List<User> userTable)
        {
            if (userTable.Any(x => x.Email == updateDto.Email && x.UserId != foundUser.UserId))
                throw CustomException.BadRequest("Email already exists, try another one");
            if (userTable.Any(x => x.Username == updateDto.Username && x.UserId != foundUser.UserId))
                throw CustomException.BadRequest("Username already exists, try another one");
            if (userTable.Any(x => x.PhoneNumber == updateDto.PhoneNumber && x.UserId != foundUser.UserId))
                throw CustomException.BadRequest("Phone number already exists, try another one");

            if (string.IsNullOrEmpty(updateDto.Email)) updateDto.Email = foundUser.Email;
            if (string.IsNullOrEmpty(updateDto.Username)) updateDto.Username = foundUser.Username;
            if (string.IsNullOrEmpty(updateDto.FirstName)) updateDto.FirstName = foundUser.FirstName;
            if (string.IsNullOrEmpty(updateDto.LastName)) updateDto.LastName = foundUser.LastName;
            if (string.IsNullOrEmpty(updateDto.PhoneNumber)) updateDto.PhoneNumber = foundUser.PhoneNumber;
            if (string.IsNullOrEmpty(updateDto.Password))
                updateDto.Password = foundUser.Password;
            else
                ValidatePassword(updateDto.Password);

            if (updateDto.BirthDate.Equals(DateOnly.Parse("0001-01-01")))
                updateDto.BirthDate = foundUser.BirthDate;

            updateDto.Role = GetUserRole(updateDto.Email);
        }

        public async Task<List<UserReadDto>> GetAllAsync()
        {
            var userList = await _userRepo.GetAllAsync();
            return _mapper.Map<List<User>, List<UserReadDto>>(userList);
        }
    }
}
