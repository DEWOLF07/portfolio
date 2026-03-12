import yfinance as yf
import matplotlib.pyplot as plt

def get_metrics(ticker, period="1y"):
    data = yf.Ticker(ticker).history(period=period)
    returns = data['Close'].pct_change().dropna()
    volatility = returns.std()
    avg_return = returns.mean()
    sharpe_ratio = avg_return / volatility if volatility != 0 else 0
    return volatility, avg_return, sharpe_ratio

if __name__ == "__main__":
    t1 = input("Enter first ticker symbol: ").upper()
    t2 = input("Enter second ticker symbol: ").upper()

    vol1, ret1, sharpe1 = get_metrics(t1)
    vol2, ret2, sharpe2 = get_metrics(t2)

    print(f"{t1}: Volatility={vol1:.4f}, Average Return={ret1:.4f}, Sharpe Ratio={sharpe1:.4f}")
    print(f"{t2}: Volatility={vol2:.4f}, Average Return={ret2:.4f}, Sharpe Ratio={sharpe2:.4f}")

    data1 = yf.Ticker(t1).history(period="1y")['Close']
    data2 = yf.Ticker(t2).history(period="1y")['Close']

    plt.plot(data1.index, data1, label=t1)
    plt.plot(data2.index, data2, label=t2)
    plt.legend()
    plt.title("Stock Price Comparison - Last 1 Year")
    plt.show()
