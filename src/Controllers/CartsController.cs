using Microsoft.AspNetCore.Mvc;

using src.Entity;
using src.Services.cart;
using src.Utils;
using static src.DTO.CartDTO;

namespace src.Controller
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class CartsController : ControllerBase

    {
        protected readonly ICartService _cartService;
        public CartsController(ICartService service)
        {
            _cartService = service;
        }
        // get all carts: GET api/v1/carts
        [HttpGet]
        public async Task<ActionResult<List<CartReadDto>>> GetAllCarts()
        {
            var cartRead = await _cartService.GetCartsAsync();
            return Ok(cartRead);
        }

        //get cart by id: GET api/v1/carts/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<CartReadDto>> GetCartById(Guid id)
        {
            var cartRead = await _cartService.GetCartByIdAsync(id);
            return Ok(cartRead);
        }

        //create new cart: POST api/v1/carts
        [HttpPost]
        public async Task<ActionResult<CartReadDto>> CreateCart([FromBody] CartCreateDto createDto)
        {
            var cartRead = await _cartService.CreateCartAsync(createDto);

            return CreatedAtAction(nameof(GetCartById), new { id = cartRead.Id }, cartRead);
        }

        //update cart: PUT api/v1/carts/{id}
        [HttpPut("{id}")]
        public async Task<ActionResult<CartReadDto>> UpdateCart(Guid id, CartUpdateDto updateDto)
        {
            var cartRead = await _cartService.UpdateCartAsync(id, updateDto);
            return Ok(cartRead);
        }

        //delete cart: DELETE api/v1/carts/{id}
        [HttpDelete("{id}")]
        public async Task<ActionResult<bool>> DeleteCartById(Guid id)
        {
            var isDeleted = await _cartService.DeleteCartByIdAsync(id);
            return Ok(isDeleted);
        }
    }
}

