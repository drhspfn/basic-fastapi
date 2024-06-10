from collections import deque
import asyncio

class Worker:
    def __init__(self, task_count: int = 5):
        self.task_count = task_count
        self.running = set()
        self.waiting = deque()

    @property
    def running_task_count(self) -> int:
        """
        Returns the number of currently running tasks.

        Parameters:
            None

        Returns:
            int: The number of currently running tasks.
        """
        return len(self.running)

    def get_running_tasks(self):
        """
        Returns a list of currently running tasks with their names and arguments.

        Parameters:
            None

        Returns:
            list: A list of dictionaries, where each dictionary contains the name and arguments of a running task.

        Note:
            The returned arguments are limited to str, int, dict, list, and tuple types.
        """
        
        data = []
        tasks = list(self.running)
        for task in tasks:
            task_name = task.__qualname__
            task_name_split = task_name.split('.')
            if len(task_name_split) > 1:
                task_name = ''.join(task_name_split[1:])

            new_args = {}
            task_frame = task.cr_frame
            if task_frame:
                task_args = task_frame.f_locals
                if 'self' in task_args:
                    del task_args['self']

                for key, value in task_args.items():
                    if isinstance(value, (str, int, dict, list, tuple)):
                        new_args[key] = value

            data.append({
                'name': task_name,
                'args': new_args,
            })
        return data
    
    def add_task(self, coro):
        """
        Adds a coroutine to the worker's task queue. If the number of running tasks is less than the task count,
        the coroutine will be started immediately. Otherwise, it will be added to the waiting queue.

        Parameters:
            coro (coroutine): The coroutine to be added to the task queue.

        Returns:
            None
        """
        
        if len(self.running) >= self.task_count:
            self.waiting.append(coro)
        else:
            self._start_task(coro)

    def _start_task(self, coro):
        """
        Adds a coroutine to the running set and starts it as a new task.

        Parameters:
            coro (coroutine): The coroutine to be added to the running set and started.

        Returns:
            None

        Note:
            This method is intended to be called internally by the Worker class.
            It adds the coroutine to the running set and starts it as a new task using asyncio.create_task().
        """
        self.running.add(coro)
        asyncio.create_task(self._task(coro))

    async def _task(self, coro):
        """
        An asynchronous method that manages the execution of coroutines.

        This method is responsible for handling exceptions, removing completed tasks from the running set,
        and starting the next waiting task if available.

        Parameters:
            coro (coroutine): The coroutine to be executed.

        Returns:
            None

        Raises:
            Any exceptions raised by the coroutine.

        Note:
            This method is intended to be called internally by the Worker class.
            It should be used as an asynchronous task using asyncio.create_task().
        """
        
        try:
            return await coro
        except:
            # Remove the failed coroutine from the running set
            self.running.remove(coro)

            # If there are waiting coroutines, start the next one
            if self.waiting:
                coro2 = self.waiting.popleft()
                self._start_task(coro2)

        finally:
            # If there are waiting coroutines, start the next one
            if self.waiting:
                coro2 = self.waiting.popleft()
                self._start_task(coro2)
