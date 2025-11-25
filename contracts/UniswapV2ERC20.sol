pragma solidity =0.5.16;

import './interfaces/IUniswapV2ERC20.sol';
import './libraries/SafeMath.sol';

// Implements the ERC20 standard along with Uniswap V2 specific minting/burning 
// and the EIP-2612 permit function for gasless approvals.
contract UniswapV2ERC20 is IUniswapV2ERC20 {
    using SafeMath for uint;

    // --- State Variables (ERC20 Standard) ---
    string public constant name = 'Uniswap V2';
    string public constant symbol = 'UNI-V2';
    uint8 public constant decimals = 18;
    uint public totalSupply;
    mapping(address => uint) public balanceOf;
    mapping(address => mapping(address => uint)) public allowance;

    // --- EIP-2612 Permit Variables ---
    bytes32 public DOMAIN_SEPARATOR;
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    mapping(address => uint) public nonces;

    // --- Events ---
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    constructor() public {
        // OPTIMIZATION: Use block.chainid directly instead of assembly for cleaner code.
        uint chainId = block.chainid;

        // Calculate the EIP-712 Domain Separator for off-chain signature signing
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
                keccak256(bytes(name)),
                keccak256(bytes('1')), // Version constant
                chainId,
                address(this)
            )
        );
    }

    // --- Internal Accounting Functions ---

    /**
     * @notice Mints new tokens to the specified address.
     * @param to The address receiving the new tokens.
     * @param value The amount of tokens to mint.
     */
    function _mint(address to, uint value) internal {
        totalSupply = totalSupply.add(value);
        balanceOf[to] = balanceOf[to].add(value);
        emit Transfer(address(0), to, value);
    }

    /**
     * @notice Burns tokens from the specified address.
     * @param from The address from which tokens are burned.
     * @param value The amount of tokens to burn.
     */
    function _burn(address from, uint value) internal {
        balanceOf[from] = balanceOf[from].sub(value);
        totalSupply = totalSupply.sub(value);
        emit Transfer(from, address(0), value);
    }

    /**
     * @dev Internal approval function.
     */
    function _approve(address owner, address spender, uint value) private {
        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    /**
     * @dev Internal transfer function. Handles the token movement and balance updates.
     */
    function _transfer(address from, address to, uint value) private {
        balanceOf[from] = balanceOf[from].sub(value);
        balanceOf[to] = balanceOf[to].add(value);
        emit Transfer(from, to, value);
    }

    // --- External/Public ERC20 Functions ---

    /**
     * @notice Allows a spender to withdraw tokens from the owner's account.
     * @param spender The address allowed to spend.
     * @param value The amount of allowance.
     * @return true on success.
     */
    function approve(address spender, uint value) external returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }

    /**
     * @notice Transfers tokens directly to another address.
     * @param to The recipient address.
     * @param value The amount to transfer.
     * @return true on success.
     */
    function transfer(address to, uint value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    /**
     * @notice Transfers tokens from one address to another, using allowance.
     * @param from The source address.
     * @param to The recipient address.
     * @param value The amount to transfer.
     * @return true on success.
     */
    function transferFrom(address from, address to, uint value) external returns (bool) {
        // Only deduct allowance if it is not the maximum possible value (infinite approval)
        if (allowance[from][msg.sender] != uint(-1)) {
            allowance[from][msg.sender] = allowance[from][msg.sender].sub(value);
        }
        _transfer(from, to, value);
        return true;
    }

    /**
     * @notice Allows users to approve a spender off-chain using an EIP-712 signature (Permit).
     * @param owner The address providing the allowance.
     * @param spender The address allowed to spend.
     * @param value The amount of allowance.
     * @param deadline The time after which the signature is invalid.
     * @param v ECDSA signature component.
     * @param r ECDSA signature component.
     * @param s ECDSA signature component.
     */
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        // Ensure the permit signature has not expired
        require(deadline >= block.timestamp, 'UniswapV2: EXPIRED');
        
        // Construct the EIP-712 digest
        bytes32 digest = keccak256(
            abi.encodePacked(
                '\x19\x01', // EIP-191 header for EIP-712
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
            )
        );
        
        // Recover the signing address
        address recoveredAddress = ecrecover(digest, v, r, s);
        
        // Ensure the recovered address is valid and matches the owner
        require(recoveredAddress != address(0) && recoveredAddress == owner, 'UniswapV2: INVALID_SIGNATURE');
        
        // Apply the approval
        _approve(owner, spender, value);
    }
}
