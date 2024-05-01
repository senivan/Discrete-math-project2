import time
import Chat_app.Encryption_algos.ECC as ecc
# import Chat_app.Encryption_algos.RSA as rsa
import psutil
import matplotlib.pyplot as plt
def time_decorator(func):
    res = []
    def wrapper(*args, **kwargs):
        for _ in range(10):
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
        # print(f"Average memory usage: {sum(res) / len(res)}")
        return sum(res) / len(res)
    return wrapper

def get_file_data():
    with open("test_file.txt", "r") as file:
        data = file.read()
    return data

if __name__ == "__main__":
    # @memory_decorator
    # def test():
    #     ecc.ECC.generate_keys()
    data = get_file_data()

    sizes = [10, 100, 1000, 3000, 5000, 10000]
    enc = []
    times = []
    key1 = ecc.ECC.generate_keys()
    key2 = ecc.ECC.generate_keys()
    symetric_key = ecc.ECC.derive_key_function(key1[0], key2[1])
    for size in sizes:
        print(f"Size: {size}")
        res = ecc.AES128.encrypt(symetric_key, data[:size].encode())
        enc.append(res)
        @memory_decorator
        def test():
            print(data[:size])
            res = ecc.AES128.encrypt(symetric_key, data[:size].encode())
            print(res)
        times.append(test())
        print("")
    
    print(times)
    plt.plot(sizes, times)
    plt.xlabel("Size")
    plt.ylabel("Memory")
    plt.show()
    times.clear()
    for e in enc:
        print(f"Size: {len(e)}")
        print(ecc.AES128.decrypt(symetric_key, e).decode())
        @memory_decorator
        def test():
            ecc.AES128.decrypt(symetric_key, e)
        times.append(test())
        print("")
    print(times)

    plt.plot(sizes, times)
    plt.xlabel("Size")
    plt.ylabel("Memory")
    plt.show()




    
    


    