using System;
using AutoMapper;
using src.Repository;
using static src.DTO.SubCategoryDTO;

namespace src.Services.SubCategory
{
    public class SubCategoryService : ISubCategoryService
    {
        private readonly SubCategoryRepository _subCategoryRepo;
        private readonly CategoryRepository _categoryRepo;
        private readonly IMapper _mapper;

        public SubCategoryService(SubCategoryRepository subCategoryRepo, CategoryRepository categoryRepo, IMapper mapper)
        {
            _subCategoryRepo = subCategoryRepo;
            _categoryRepo = categoryRepo;
            _mapper = mapper;
        }

   

        // public async Task <SubCategoryReadDto> CreateOneAsync(SubCategoryCreateDto createDto)
        // {
        //     var subCategory = _mapper.Map <SubCategoryCreateDto, src.Entity.SubCategory>(createDto);
        //     var subCategoryCreated = await _subCategoryRepo.CreateSubCategory(subCategory);
        //     return _mapper.Map <src.Entity.SubCategory,SubCategoryReadDto> (subCategoryCreated);
        // }
        public async Task<SubCategoryReadDto> CreateOneAsync(Guid id, SubCategoryCreateDto createDto)
        {
            // Check if the category exists first
            var category = await _subCategoryRepo.GetByIdAsync(id);
            if (category == null) 
                return null;

            var newSubCategory = new src.Entity.SubCategory
            {
                Name = createDto.Name,
                SubCategoryId = id // Ensure the subcategory is linked to the category
            };

            await _subCategoryRepo.CreateOneAsync(newSubCategory);
            return _mapper.Map<src.Entity.SubCategory, SubCategoryReadDto>(newSubCategory);
        }


        
        public async Task<List<SubCategoryReadDto>> GetAllAsync()
        {
            var subCategoryList = await _subCategoryRepo.GetAllAsync();
            return _mapper.Map<List<src.Entity.SubCategory>, List<SubCategoryReadDto>>(subCategoryList);
        }

        public async Task<SubCategoryReadDto> GetByCategoryIdAsync(Guid id)
        {
            var foundSubCategory = await _subCategoryRepo.GetByIdAsync(id);
            return _mapper.Map<src.Entity.SubCategory, SubCategoryReadDto> (foundSubCategory);
        }

        public async Task<bool> DeleteOneAsync(Guid subCategoryId)
        {
            var foundSubCategory = await _subCategoryRepo.GetByIdAsync(subCategoryId);
            bool isDeleted = await _subCategoryRepo.DeleteOneAsync(foundSubCategory);
            return isDeleted;
        }

        public async Task<bool> UpdateOneAsync(Guid id, Guid subCategoryId, SubCategoryUpdateDto updateDto)
        {
            var foundSubCategory = await _subCategoryRepo.GetByIdAsync(subCategoryId);
            var isUpdated = await _subCategoryRepo.UpdateOneAsync(foundSubCategory);

            if (foundSubCategory==null)
            {
                return false;
            }

            // _mapper.Map(updateDto, foundSubCategory);
            return await _subCategoryRepo.UpdateOneAsync(foundSubCategory); 
        }

        public Task<List<SubCategoryReadDto>> GetAllAsynac()
        {
            throw new NotImplementedException();
        }

        public Task<SubCategoryReadDto> GetByIdAsynac(Guid subCategoryId)
        {
            throw new NotImplementedException();
        }

        public Task<bool> UpdateOneAsync(Guid subCategoryId, SubCategoryUpdateDto updateDto)
        {
            throw new NotImplementedException();
        }

        public Task<bool> DeleteOneAsync(string name)
        {
            throw new NotImplementedException();
        }

        public Task<bool> DeleteOneAsync(Guid id, Guid subCategoryId)
        {
            throw new NotImplementedException();
        }

        public Task CreateOneAsync(Entity.SubCategory subCategory)
        {
            throw new NotImplementedException();
        }

        public Task<SubCategoryReadDto> CreateOneAsync(SubCategoryCreateDto createDto)
        {
            throw new NotImplementedException();
        }

        public Task<SubCategoryReadDto> GetByIdAsync(Guid subCategoryId)
        {
            throw new NotImplementedException();
        }
    }
}