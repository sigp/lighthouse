## CPU

|                                                                                        | Linux              | macOS              | Windows            |
|----------------------------------------------------------------------------------------|--------------------|--------------------|--------------------|
| [cpu_times](https://psutil.readthedocs.io/en/latest/#psutil.cpu_times)                 | :heavy_check_mark: | :heavy_check_mark: |                    |
| [cpu_percent](https://psutil.readthedocs.io/en/latest/#psutil.cpu_percent)             | :heavy_check_mark: | :heavy_check_mark: |                    |
| [cpu_times_percent](https://psutil.readthedocs.io/en/latest/#psutil.cpu_times_percent) | :heavy_check_mark: | :heavy_check_mark: |                    |
| [cpu_count](https://psutil.readthedocs.io/en/latest/#psutil.cpu_count)                 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| [cpu_stats](https://psutil.readthedocs.io/en/latest/#psutil.cpu_stats)                 |                    |                    |                    |
| [cpu_freq](https://psutil.readthedocs.io/en/latest/#psutil.cpu_freq)                   |                    |                    |                    |

## Disk

|                                                                                      | Linux              | macOS              | Windows |
|--------------------------------------------------------------------------------------|--------------------|--------------------|---------|
| [disk_partitions](https://psutil.readthedocs.io/en/latest/#psutil.disk_partitions)   | :heavy_check_mark: | :heavy_check_mark: |         |
| [disk_usage](https://psutil.readthedocs.io/en/latest/#psutil.disk_usage)             | :heavy_check_mark: | :heavy_check_mark: |         |
| [disk_io_counters](https://psutil.readthedocs.io/en/latest/#psutil.disk_io_counters) | :heavy_check_mark: |                    |         |

## Host

|                                                                                    | Linux              | macOS | Windows |
|------------------------------------------------------------------------------------|--------------------|-------|---------|
| [loadavg](https://psutil.readthedocs.io/en/latest/?badge=latest#psutil.getloadavg) | :heavy_check_mark: |       |         |
| [boot_time](https://psutil.readthedocs.io/en/latest/#psutil.boot_time)             | :heavy_check_mark: |       |         |
| [users](https://psutil.readthedocs.io/en/latest/#psutil.users)                     |                    |       |         |

## Memory

|                                                                                  | Linux              | macOS              | Windows |
|----------------------------------------------------------------------------------|--------------------|--------------------|---------|
| [virtual_memory](https://psutil.readthedocs.io/en/latest/#psutil.virtual_memory) | :heavy_check_mark: | :heavy_check_mark: |         |
| [swap_memory](https://psutil.readthedocs.io/en/latest/#psutil.swap_memory)       | :heavy_check_mark: | :heavy_check_mark: |         |

## Network

|                                                                                    | Linux              | macOS              | Windows |
|------------------------------------------------------------------------------------|--------------------|--------------------|---------|
| [net_io_counters](https://psutil.readthedocs.io/en/latest/#psutil.net_io_counters) | :heavy_check_mark: | :heavy_check_mark: |         |
| [net_connections](https://psutil.readthedocs.io/en/latest/#psutil.net_connections) |                    |                    |         |
| [net_if_addrs](https://psutil.readthedocs.io/en/latest/#psutil.net_if_addrs)       |                    |                    |         |
| [net_if_stats](https://psutil.readthedocs.io/en/latest/#psutil.net_if_stats)       |                    |                    |         |

## Processes

|                                                                              | Linux              | macOS              | Windows |
|------------------------------------------------------------------------------|--------------------|--------------------|---------|
| [pids](https://psutil.readthedocs.io/en/latest/#psutil.pids)                 | :heavy_check_mark: | :heavy_check_mark: |         |
| [process_iter](https://psutil.readthedocs.io/en/latest/#psutil.process_iter) | :heavy_check_mark: | :heavy_check_mark: |         |
| [pid_exists](https://psutil.readthedocs.io/en/latest/#psutil.pid_exists)     | :heavy_check_mark: |                    |         |
| [wait_procs](https://psutil.readthedocs.io/en/latest/#psutil.wait_procs)     |                    |                    |         |

### Per-process

|                                                                                              | Linux              | macOS              | Windows |
|----------------------------------------------------------------------------------------------|--------------------|--------------------|---------|
| [pid](https://psutil.readthedocs.io/en/latest/#psutil.Process.pid)                           | :heavy_check_mark: | :heavy_check_mark: |         |
| [ppid](https://psutil.readthedocs.io/en/latest/#psutil.Process.ppid)                         | :heavy_check_mark: |                    |         |
| [name](https://psutil.readthedocs.io/en/latest/#psutil.Process.name)                         | :heavy_check_mark: | :heavy_check_mark: |         |
| [exe](https://psutil.readthedocs.io/en/latest/#psutil.Process.exe)                           | :heavy_check_mark: |                    |         |
| [cmdline](https://psutil.readthedocs.io/en/latest/#psutil.Process.cmdline)                   | :heavy_check_mark: |                    |         |
| [environ](https://psutil.readthedocs.io/en/latest/#psutil.Process.environ)                   | :heavy_check_mark: |                    |         |
| [create_time](https://psutil.readthedocs.io/en/latest/#psutil.Process.create_time)           | :heavy_check_mark: | :heavy_check_mark: |         |
| [as_dict](https://psutil.readthedocs.io/en/latest/#psutil.Process.as_dict)                   |                    |                    |         |
| [parent](https://psutil.readthedocs.io/en/latest/#psutil.Process.parent)                     | :heavy_check_mark: |                    |         |
| [parents](https://psutil.readthedocs.io/en/latest/#psutil.Process.parents)                   |                    |                    |         |
| [status](https://psutil.readthedocs.io/en/latest/#psutil.Process.status)                     | :heavy_check_mark: |                    |         |
| [cwd](https://psutil.readthedocs.io/en/latest/#psutil.Process.cwd)                           | :heavy_check_mark: |                    |         |
| [username](https://psutil.readthedocs.io/en/latest/#psutil.Process.username)                 |                    |                    |         |
| [uids](https://psutil.readthedocs.io/en/latest/#psutil.Process.uids)                         | :heavy_check_mark: |                    |         |
| [gids](https://psutil.readthedocs.io/en/latest/#psutil.Process.gids)                         | :heavy_check_mark: |                    |         |
| [terminal](https://psutil.readthedocs.io/en/latest/#psutil.Process.terminal)                 |                    |                    |         |
| [nice](https://psutil.readthedocs.io/en/latest/#psutil.Process.nice)                         |                    |                    |         |
| [ionice](https://psutil.readthedocs.io/en/latest/#psutil.Process.ionice)                     |                    |                    |         |
| [rlimit](https://psutil.readthedocs.io/en/latest/#psutil.Process.rlimit)                     |                    |                    |         |
| [io_counters](https://psutil.readthedocs.io/en/latest/#psutil.Process.io_counters)           |                    |                    |         |
| [num_ctx_switches](https://psutil.readthedocs.io/en/latest/#psutil.Process.num_ctx_switches) |                    |                    |         |
| [num_fds](https://psutil.readthedocs.io/en/latest/#psutil.Process.num_fds)                   |                    |                    |         |
| [num_threads](https://psutil.readthedocs.io/en/latest/#psutil.Process.num_threads)           |                    |                    |         |
| [threads](https://psutil.readthedocs.io/en/latest/#psutil.Process.threads)                   |                    |                    |         |
| [cpu_times](https://psutil.readthedocs.io/en/latest/#psutil.Process.cpu_times)               | :heavy_check_mark: | :heavy_check_mark: |         |
| [cpu_percent](https://psutil.readthedocs.io/en/latest/#psutil.Process.cpu_percent)           | :heavy_check_mark: | :heavy_check_mark: |         |
| [cpu_affinity](https://psutil.readthedocs.io/en/latest/#psutil.Process.cpu_affinity)         |                    |                    |         |
| [cpu_num](https://psutil.readthedocs.io/en/latest/#psutil.Process.cpu_num)                   |                    |                    |         |
| [memory_info](https://psutil.readthedocs.io/en/latest/#psutil.Process.memory_info)           | :heavy_check_mark: | :heavy_check_mark: |         |
| [memory_info_full](https://psutil.readthedocs.io/en/latest/#psutil.Process.memory_info_full) |                    |                    |         |
| [memory_percent](https://psutil.readthedocs.io/en/latest/#psutil.Process.memory_percent)     | :heavy_check_mark: | :heavy_check_mark: |         |
| [memory_maps](https://psutil.readthedocs.io/en/latest/#psutil.Process.memory_maps)           |                    |                    |         |
| [children](https://psutil.readthedocs.io/en/latest/#psutil.Process.children)                 |                    |                    |         |
| [open_files](https://psutil.readthedocs.io/en/latest/#psutil.Process.open_files)             | :heavy_check_mark: |                    |         |
| [connections](https://psutil.readthedocs.io/en/latest/#psutil.Process.connections)           |                    |                    |         |
| [is_running](https://psutil.readthedocs.io/en/latest/#psutil.Process.is_running)             | :heavy_check_mark: | :heavy_check_mark: |         |
| [send_signal](https://psutil.readthedocs.io/en/latest/#psutil.Process.send_signal)           | :heavy_check_mark: | :heavy_check_mark: |         |
| [suspend](https://psutil.readthedocs.io/en/latest/#psutil.Process.suspend)                   | :heavy_check_mark: | :heavy_check_mark: |         |
| [resume](https://psutil.readthedocs.io/en/latest/#psutil.Process.resume)                     | :heavy_check_mark: | :heavy_check_mark: |         |
| [terminate](https://psutil.readthedocs.io/en/latest/#psutil.Process.terminate)               | :heavy_check_mark: | :heavy_check_mark: |         |
| [kill](https://psutil.readthedocs.io/en/latest/#psutil.Process.kill)                         | :heavy_check_mark: | :heavy_check_mark: |         |
| [wait](https://psutil.readthedocs.io/en/latest/#psutil.Process.wait)                         |                    |                    |         |

## Sensors

|                                                                                              | Linux              | macOS | Windows |
|----------------------------------------------------------------------------------------------|--------------------|-------|---------|
| [sensors_temperatures](https://psutil.readthedocs.io/en/latest/#psutil.sensors_temperatures) | :heavy_check_mark: |       |         |
| [sensors_fans](https://psutil.readthedocs.io/en/latest/#psutil.sensors_fans)                 |                    |       |         |

## New functionality

|        | Linux              | macOS              | Windows |
|--------|--------------------|--------------------|---------|
| Info   | :heavy_check_mark: | :heavy_check_mark: |         |
| uptime | :heavy_check_mark: |                    |         |
