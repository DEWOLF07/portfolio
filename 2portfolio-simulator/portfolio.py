class OptionPosition:
    def __init__(self, strike, premium, quantity, option_type):
        self.strike = strike        # strike price
        self.premium = premium      # option premium paid/received
        self.quantity = quantity    # positive = long, negative = short
        self.option_type = option_type.lower()  # 'call' or 'put'

    def payoff(self, stock_price):
        if self.option_type == 'call':
            intrinsic = max(stock_price - self.strike, 0)
        else:
            intrinsic = max(self.strike - stock_price, 0)
        return (intrinsic - self.premium) * self.quantity

class Portfolio:
    def __init__(self):
        self.positions = []

    def add_position(self, pos):
        self.positions.append(pos)

    def total_payoff(self, stock_price):
        return sum(p.payoff(stock_price) for p in self.positions)

if __name__ == "__main__":
    p = Portfolio()

    # Example positions:
    p.add_position(OptionPosition(strike=100, premium=5, quantity=1, option_type='call'))
    p.add_position(OptionPosition(strike=95, premium=3, quantity=-2, option_type='put'))

    print("Stock Price | Portfolio P/L")
    for price in range(80, 121, 5):
        pl = p.total_payoff(price)
        print(f"{price:10} | {pl: .2f}")
