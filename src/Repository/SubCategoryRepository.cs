using System;
using Microsoft.EntityFrameworkCore;
using src.Database;
using src.Entity;
using src.Utils;

namespace src.Repository
{
    public class SubCategoryRepository
    {
        protected DbSet<SubCategory> _subCategories;
        protected DatabaseContext _databaseContext;

        public SubCategoryRepository(DatabaseContext databaseContext)
        {
            _databaseContext = databaseContext;
            _subCategories =databaseContext.Set<SubCategory>();
        }

        public async Task<SubCategory> CreateOneAsync(SubCategory newSubCategory)
        {
            await _subCategories.AddAsync(newSubCategory);
            await _databaseContext.SaveChangesAsync();
            return newSubCategory;
        }
        public async Task<SubCategory> AddAsync(SubCategory newSubCategory)
        {
            // Add the subcategory entity to the DbSet
            await _subCategories.AddAsync(newSubCategory);
            await _databaseContext.SaveChangesAsync();
            return newSubCategory;
        }
 

        public async Task<List<SubCategory>> GetAllAsync()
{

        return await _subCategories.Include(sb => sb.Category).ToListAsync();

    
}

        
        // public async Task<List<SubCategory>> GetAllAsync()
        // {
        //     return await _subCategories.ToListAsync();
        // }
        // // public async Task<List<SubCategory>> GetByIdAsync()
        // // {
        // //     return await _subCategories.ToListAsync();
        // // }
        public async Task<SubCategory> GetByIdAsync(Guid subCategoryId)
        {
            return await _subCategories.Include(sb=>sb.Category).FirstOrDefaultAsync(sb=>sb.SubCategoryId==subCategoryId);
        }

        public async Task<bool> DeleteOneAsync(SubCategory subCategory)
        {
            _subCategories.Remove(subCategory);
            await _databaseContext.SaveChangesAsync();
            return true;
        }  
         public async Task<bool> UpdateOneAsync(SubCategory updateSubCategory)
        // public async Task<SubCategory> UpdateOneAsync(SubCategory updateSubCategory)
        {
            _subCategories.Update(updateSubCategory);
            await _databaseContext.SaveChangesAsync();
            return true;
            // return updateSubCategory;
        }

        
        // public async Task<List<SubCategory>> GetAllResults(PaginationOptions paginationOptions)
        // { // check the naming 
        //     var result = _subCategories.Where(sc =>
        //         sc.Name.ToLower().Contains(paginationOptions.Search.ToLower())
        //     );
        //     return await result
        //         .Skip(paginationOptions.Offset)
        //         .Take(paginationOptions.Limit)
        //         .ToListAsync();
        // }
    }
}   