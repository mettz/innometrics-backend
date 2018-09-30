"""
Helper functions
"""
from multiprocessing.pool import ThreadPool, Pool
from typing import Callable, List

NUM_OF_THREADS = 15
thread_pool = None

NUM_OF_PROCESSES = 10
process_pool = None


def execute_function_in_parallel(func: Callable, list_args: List, processes: bool = False,
                                 local_pool: bool = False, num_threads: int = NUM_OF_THREADS,
                                 num_processes: int = NUM_OF_PROCESSES) -> List:
    """
    Execute a function in parallel using ThreadPool or ProcessPool
    :param local_pool: create a new pool of threads/processes
    :param num_processes: a num of processes to create
    :param num_threads: a num of threads to create
    :param processes: execute tasks in separate processes
    :param func: a func to call
    :param list_args: an array containing calling params
    :return: an array with results
    """
    if not (func and list_args):
        return []

    if local_pool:
        pool = ThreadPool(num_threads) if not processes else Pool(num_processes)
    else:
        global process_pool
        if processes:
            if not process_pool:
                process_pool = Pool(NUM_OF_PROCESSES)
            pool = process_pool
        else:
            global thread_pool
            if not thread_pool:
                thread_pool = ThreadPool(NUM_OF_THREADS)
            pool = thread_pool
    results_tmp = pool.starmap_async(func, list_args)
    results = [result for result in results_tmp.get() if result is not None]
    if local_pool:
        pool.close()
    return results
