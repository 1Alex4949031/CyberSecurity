// SPDX-License-Identifier: MIT

pragma solidity ^0.8.22;

contract GameShop {
    address owner;

    // Структура для игры.
    struct Game {
        uint id;
        string title;
        uint price;
        uint count;
    }

    // Для простоты.
    uint id_games = 0;

    // Ассоциативный массив игр.
    mapping(uint => Game) public gamesMap;

    // События.
    event gameAdded(string title, uint price);
    event oneGameAdded(string title, uint price);
    event gamePurchased(string title, uint price, address purchaser);

    constructor() {
        owner = msg.sender;
    }

    // Модификатор доступа только для владельца магазина.
    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can perform this action");
        _;
    }

    // Функция для добавления игры в магазин.
    function addGame(string memory title, uint price, uint count) public onlyOwner {
        require(bytes(title).length > 0, "Game must have a title");
        require(price > 0, "Price must be positive");
        require(count > 0, "Count of games must be positive");

        Game memory newGame = Game(id_games, title, price, count);
        gamesMap[id_games] = newGame;
        id_games++;

        emit gameAdded(title, price);
    }

    // Функция для получения списка всех игр.
    function getGames() public view returns (Game[] memory) {
        Game[] memory games = new Game[](id_games);
        for (uint i = 0; i < id_games; i++) {
            games[i] = gamesMap[i];
        }
        return games;
    }

    // Функция для добавления одной существующий игры.
    function incExisting(uint gameId) public onlyOwner {
        require(gameId < id_games, "This game does not exist");

        Game storage gameToAdd = gamesMap[gameId];
        gameToAdd.count += 1;
        emit oneGameAdded(gameToAdd.title, gameToAdd.price);
    }

    // Функция для покупки игры.
    function buyGame(uint gameId) public payable {
        require(gameId < id_games, "This game does not exist");
    
        Game storage gameToBuy = gamesMap[gameId];
        require(gameToBuy.count > 0, "This game is not available for purchase");
        require(msg.value == gameToBuy.price, "Incorrect amount of Ether sent");

        gameToBuy.count -= 1;
        emit gamePurchased(gameToBuy.title, gameToBuy.price, msg.sender);
    }

    // Функция для снятия денег со счета контракта.
    function withdrawFunds() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // Прием эфира в контракт.
    receive() external payable {}
}
