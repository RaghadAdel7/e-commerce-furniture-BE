using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoMapper;
using src.Repository;
using src.Controllers;
using static src.DTO.UserDTO;
using src.Entity;


namespace src.Services.user
{
    public class UserService : IUserService
    {
        protected readonly UserRepository _userRepo;
        protected readonly IMapper _mapper;
        public UserService(UserRepository userRepo , IMapper mapper)
        {
            _userRepo = userRepo;
            _mapper = mapper;
        }
        public async Task<UserReadDto> CreateOneAsync(UserCreateDto createDto)
        {
            var user = _mapper.Map<UserCreateDto, User>(createDto);
            var userCreated = await _userRepo.CreateOneAsync(user);
            return _mapper.Map<User, UserReadDto>(userCreated);
        }
        // get all
        public async Task<List<UserReadDto>> GetAllAsync()
        {
            var userList = await _userRepo.GetAllAsync();
            return _mapper.Map<List<User>, List<UserReadDto>>(userList);
        }
        // get by id
        public async Task<UserReadDto> GetByIdAsync(Guid id)
        {
            var foundUser = await _userRepo.GetByIdAsync(id);
            return _mapper.Map<User, UserReadDto>(foundUser);
        }
        // delete 
        public async Task<bool> DeleteOneAsync(Guid id)
        {
            var foundUser = await _userRepo.GetByIdAsync(id);
            bool isDeleted = await _userRepo.DeleteOneAsync(foundUser);
            if(isDeleted)
            {
                return true;
            }
            return false;
        }
        // update
        public async Task<bool> UpdateOneAsync(Guid id , UserUpdateDto updateDto)
        {
            var foundUser = await _userRepo.GetByIdAsync(id);
            if(foundUser == null)
            {
                return false;
            }
            _mapper.Map(updateDto, foundUser);
            return await _userRepo.UpdateOneAsync(foundUser);
        }
    }
}