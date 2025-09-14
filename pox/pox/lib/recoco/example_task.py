# Copyright 2024 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A simple Recoco example.

This is a simple component written to show how to write blocking recoco
functions (that is, functions that call recoco blocking operations or
other blocking recoco functions), and how to call those from a recoco
task or another recoco blocking function.  recoco predates Python's
async stuff, but is roughly similar, so we compare the steps involved
to async/asyncio stuff for illustration purposes.

In short, writing blocking recoco functions requires:
  1. Decorate blocking functions with @task_function.  This is much like
     defining an 'async' function.
  2. Call blocking functions (and recoco blocking operations like Sleep)
     using yield.  This is much like calling an async function with 'await'.
  3. Return values from blocking functions with yield, not return.
  4. Create a subclass of Task and override the run() method (you could
     also use the Task constructor's target parameter, much like Thread).
     This is similar to asyncio.create_task().

The above is compatible even with old Python.  With newer Python, you
can also do it more simply.  Skip #1 and #3 above, and for #2, use "yield
from" to call blocking functions.  This component demonstrates both ways:

_my_functions_function() is written the old way, and works with old Python.
It uses the @task_function decorator, uses "yield" to return a value, and
is called with "yield" (by _my_func()).

 _my_func() is written "the new way", which only works with Python 3.3+.
It has no decorator, uses "return" to return a value, and is called using
"yield from" (by run()).

You can run this component and specify how many test tasks to create
with a command line like:
  ./pox.py pox.lib.recoco.example_task=3
"""

from pox.lib.recoco import Task, task_function, Sleep
from pox.core import core


class ExampleTask (Task):
  def __init__ (self, num):
    super().__init__()
    self.num = num
    self.log = core.getLogger(f"Task{num}")

  @task_function
  def _my_functions_function (self, i):
    self.log.info(f"  Iteration {i}")
    yield Sleep(2)
    yield (i+1) * 2

  def _my_func (self):
    total_wait = 0
    for i in range(5):
      # Call a task_function-style blocking function with "yield"
      total_wait = yield self._my_functions_function(i)
    return total_wait

  def run (self):
    yield Sleep(1 + self.num * 0.5)
    self.log.info("Task is calling a blocking function...")
    # Call a non-task_function-style blocking function with "yield from"
    total = yield from self._my_func()
    self.log.info(f"Task finished.  Total sleep time: {total}")
    core.quit()


def launch (count = 1):
  for i in range(int(count)):
    ExampleTask(i).start()
