import time
# import Chat_app.Encryption_algos.ECC as ecc
import Chat_app.Encryption_algos.RSA as rsa
import psutil
import matplotlib.pyplot as plt

def time_decorator(func):
    res = []
    def wrapper(*args, **kwargs):
        for _ in range(1000):
            start = time.time()
            func(*args, **kwargs)
            end = time.time()
            res.append(end - start)
        return sum(res) / len(res)
    return wrapper

def memory_decorator(func):
    def wrapper(*args, **kwargs):
        res = []
        for _ in range(1000):
            process = psutil.Process()
            start = process.memory_info().rss
            func(*args, **kwargs)
            end = process.memory_info().rss
            res.append(end - start)
            print(f"Memory usage: {end - start}")
        print(f"Average memory usage: {sum(res) / len(res)}")
        return sum(res) / len(res)
    return wrapper


def get_file_data():
    with open("test_file.txt", "r") as file:
        data = file.read()
    return data

if __name__ == "__main__":
    # @memory_decorator
    # def test():
    #     rsa.generateRSAkeys()
    pub_key, priv_key = rsa.generateRSAkeys()
    print(f"Public key: {pub_key}")
    print(f"Private key: {priv_key}")
    data = get_file_data()
    sizes = [10, 100, 500, 1000, 5000, 10000]
    times = []
    enc = []
    for size in sizes:
        enc.append(rsa.encrypt(data[:size], pub_key))
        @memory_decorator
        def test():
            rsa.encrypt(data[:size], pub_key)
        times.append(test())
    plt.plot(sizes, times)
    plt.xlabel("Data size")
    plt.ylabel("Memory")
    plt.show()

    times.clear()
    for enc in enc:
        @memory_decorator
        def test1():
            print(rsa.decrypt(enc, priv_key))
        times.append(test1())
    
    plt.plot(sizes, times)
    plt.xlabel("Data size")
    plt.ylabel("Memory")
    plt.show()
    





    
    


    