"""PyFilesystem interface for items in Box."""
from io import StringIO
import datetime

import iso8601
import logging
import requests
import urlparse
import ujson
from collections import namedtuple

from fs.base import (
    FS,
    synchronize,
    NullFile)
from fs.errors import (
    CreateFailedError,
    DestinationExistsError,
    ParentDirectoryMissingError,
    PathError,
    ResourceInvalidError,
    ResourceNotFoundError,
    )
from fs.path import (
    basename,
    iteratepath,
    normpath,
    pathjoin,
    pathsplit,
    )


__author__ = 'kparmar'


_ITEM_TYPE_FILE = 'file'
_ITEM_TYPE_FOLDER = 'folder'

_logger = logging.getLogger('fs.boxfs')

_box_api_base_url = 'https://api.box.com/2.0/'

def _is_failed_status_code(status_code):
    """Returns whether the status code indicates failure."""
    return status_code < 200 or status_code > 299

def _api_request(fs,
                 method,
                 resource,
                 params=None,
                 data=None,
                 raw_data=None,
                 headers=None,
                 files=None,
                 expect_json_response=True):
    """Make an API call.

    :param method:
      Method to use for the call.
    :type method:
      `str`

    :param resource:
      The resource being accessed.
    :type resource:
      `str`

    :param params:
      Parameters to be sent in the query string of the call.
    :type params:
      `dict`

    :param data:
      The data to send in the body of the request.
    :type data:
      `dict`

    :param headers:
      The headers to use for the call.
    :type headers:
      `dict`

    :returns:
      A tuple of the status code of the response and the response itself.
    :rtype:
      `tuple`
    """
    global _is_failed_status_code
    url = urlparse.urljoin(_box_api_base_url, resource)
    if data:
        data = ujson.encode(data)
    if raw_data:
        data = raw_data
    if headers:
        headers.update(fs._default_headers)
    else:
        headers = fs._default_headers
    response = requests.request(
        method,
        url,
        params=params,
        data=data,
        headers=headers,
        files=files
    )
    if expect_json_response:
        content = ''
        if response.content:
            content = ujson.decode(response.content)
    else:
        content = response.content

    if _is_failed_status_code(response.status_code):
        _logger.info('%s %s failed with reponse %s', method, url, content)
    return response.status_code, content


class BoxFile(NullFile):
    def __init__(self, fs, path):
        self._fs = fs
        self._path = path

    def get_info(self):
        path = self._path
        if not path:
            raise PathError(path)

        path = normpath(path)

        return self._fs.getinfo(path)

    def write(self, data):
        path = self._path
        if not path:
            raise PathError(path)

        path = normpath(path)

        item_info = self._fs.getinfo(path)
        if item_info['is_dir']:
            raise ResourceInvalidError(path)

        content_stream = StringIO(unicode(data))

        status_code, item = _api_request(
            self._fs,
            'POST',
            'files/{}/content'.format(item_info['id']),
            files={basename(path): content_stream},
            headers={'If-Match': str(item_info['sha1'])},
        )
        return item

    def read(self, size=None):
        path = self._path
        if not path:
            raise PathError(path)

        path = normpath(path)

        item_info = self._fs.getinfo(path)
        if item_info['is_dir']:
            raise ResourceInvalidError(path)

        status_code, content = _api_request(
            self._fs,
            'GET',
            'files/{}/content'.format(item_info['id']),
            expect_json_response=False)

        return str(content)

    def close(self):
        pass

class BoxNode(object):

    def __init__(self, item, path=None):
        self._item = item
        self.name = item['name']
        self.id = item['id']
        self.children = []
        self.parent = None
        self.path = path

    @classmethod
    def root(cls):
        root_item = {
            'name': '',
            'id': '0'
        }
        return BoxNode(root_item, '/')

    def add_child(self, child):
        self.children.append(child)
        child.parent = self
        pathstr = '{}{}' if self.is_root() else '{}/{}'
        child.path = pathstr.format(self.path, child.name)

    def add_all_children(self, items):
        """NASTEH GUARANTEED N^2 IN UR FACE"""
        for item in items:
            if item['parent']['id'] == self.id:
                child = BoxNode(item)
                self.add_child(child)
                child.add_all_children(items)

    def is_root(self):
        return self.id == '0'

    def is_file(self):
        return self._item['type'] == 'file'

    def is_folder(self):
        return self._item['type'] == 'folder'

    @property
    def child_names(self):
        return [child.name for child in self.children if child.is_file()]

    def breadth_first(self):
        yield (self.path, self.child_names)
        for child in [child for child in self.children if child.is_folder()]:
            for value in child.breadth_first():
                yield value

    def depth_first(self):
        for child in self.children:
            for value in child.depth_first():
                yield value
            yield (child.path, child.child_names)
        if self.root():
            yield (self.path, self.child_names)


class BoxFS(FS):
    """A filesystem stored in Box."""


    def __init__(self,
                 auth_token,
                 api_key,
                 root_id='0',
                 thread_synchronize=True):
        """
        :param auth_token:
          Authentication token to use.
        :type auth_token:
          `str`
        :param api_key:
          The API key to use to make API calls.
        :type api_key:
          `str`
        :param root_id:
          The id of the root folder.
        :type root_id:
          `str`
        """
        super(BoxFS, self).__init__(thread_synchronize=thread_synchronize)

        self._logger = logging.getLogger('fs.boxfs')
        self._api_key = api_key
        self._auth_token = auth_token
        self._root_id = root_id

        if not self._api_key:
            raise CreateFailedError('api_key not set')
        if not self._auth_token:
            raise CreateFailedError('auth_token not set')

        self._default_headers = {
            'Authorization': 'BoxAuth api_key={}&auth_token={}'.format(
                self._api_key,
                self._auth_token
            ),
            }

    def error_result(self, code, result):
        if code != 200:
            print('Error {} - {}'.format(code, result['message']))
            return True
        else:
            return False

    def _get_children_items(self, box_id):
        global _api_request
        result = {}
        status_code, items = _api_request(
            self,
            'GET',
            'folders/{}/items?fields=sync_state,name'.format(box_id)
        )
        if self.error_result(status_code, items):
            return {}

        # This is a hack because 'marked_for_sync' not properly reflected on box.
        try:
            for item in items['entries']:
                if box_id != 0:# or (item['type'] == 'file') or ('marked_for_sync' in item and item['marked_for_sync'] != 'not_synced'):
                    result[item['name']] = item
        except Exception as ex:
            print 'Result: {}', result
            raise

        return result


    def _get_item_by_path(self, path):
        """Returns the item at given path.

        :param path:
          The normalized path of the item.
        :type path:
          `str`

        :returns:
          The item as returned by the API call. Example Response:
            {
              "type":"file",
              "id":"2305649799",
              "sequence_id":"1",
              "name":"testing.html"
            }
        :rtype:
          `dict`
        """
        if path == '/':
            return {
                'type': _ITEM_TYPE_FOLDER,
                'id': self._root_id,
                # TODO(kunal): find correct value for this field.
                'sequence_id': '1',
                'name': path,
                }

        parent_box_id = self._root_id
        parent_path, item_name = pathsplit(path)
        for name in iteratepath(parent_path):
            items = self._get_children_items(parent_box_id)
            item = items.get(name)
            if not item or item['type'] != _ITEM_TYPE_FOLDER:
                print('failed to get folder {}: {}'.format(name, item))
                raise ParentDirectoryMissingError(path)

            parent_box_id = item['id']

        items = self._get_children_items(parent_box_id)
        return items.get(item_name)


    def _makedir(self, parent_box_id, name):
        """Create a directory.

        :param parent_box_id:
          The id of the parent.
        :type parent_box_id:
          `str`

        :param name:
          The name of the directory to create.
        :type name:
          `str`.

        :returns:
          Response from the API call.
        :rtype:
          `dict`
        """
        global _api_request
        status_code, item = _api_request(
            self,
            'POST',
            'folders',
            # Mark new folders to be synced.
            data={'name': name, 'parent': {'id': parent_box_id}, 'sync_state': 'synced'},
        )
        # As a workaround for BOX-58521, mark newly created folders as synced.
        # Note that this causes a full scan of that folder, which is not needed in this case.
        # return self._mark_folder_as_synced(item['id'])
        return item

    def _mark_folder_as_synced(self, parent_box_id):
        """Mark a folder as synced on Box

        :param parent_box_id:
          The id of the parent.
        :type parent_box_id:
          `str`
        """

        status_code, item = _api_request(
            self,
            'PUT',
            'folders/{}'.format(parent_box_id),
            data={'sync_state': 'synced'},
        )
        return item

    def createfile(self, path, data=None):
        """Creates an empty file if it doesn't exist
        """
        global _api_request
        parent_box_id, name = self._get_parent_box_id_from_path(path, recursive=False, allow_recreate=False)

        if not data:
            content_stream = StringIO(u'this is a dummy content stream')
        else:
            content_stream = StringIO(data)

        status_code, item = _api_request(
            self,
            'POST',
            'files/content',
            raw_data={'folder_id': parent_box_id},
            files={'file': (name, content_stream)}
        )
        return item

    def open(self, path, mode="r", **kwargs):
        return BoxFile(self, path)

    def makedir(self, path, recursive=False, allow_recreate=False):
        parent_box_id, dirname = self._get_parent_box_id_from_path(path, recursive, allow_recreate)
        self._makedir(parent_box_id, dirname)

    def _get_parent_box_id_from_path(self, path, recursive, allow_recreate):
        if not path and not allow_recreate:
            raise PathError(path)

        path = normpath(path)
        if path in ('', '/'):
            if allow_recreate:
                return
            raise DestinationExistsError(path)

        parent_path, dirname = pathsplit(path)
        parent_box_id = self._root_id
        for name in iteratepath(parent_path):
            children_items = self._get_children_items(parent_box_id)
            child_item = children_items.get(name)
            if not child_item:
                if recursive:
                    child_item = self._makedir(parent_box_id, name)
                else:
                    raise ParentDirectoryMissingError(path)

            if child_item['type'] != _ITEM_TYPE_FOLDER:
                raise ResourceInvalidError(path)

            parent_box_id = child_item['id']

        # Check if an item with required name already exists.
        children_items = self._get_children_items(parent_box_id)
        child_item = children_items.get(dirname)
        if child_item:
            if allow_recreate and child_item['type'] == _ITEM_TYPE_FOLDER:
                return parent_box_id, dirname
            elif child_item['type'] != _ITEM_TYPE_FILE:
                raise DestinationExistsError(path)

        return parent_box_id, dirname

    @synchronize
    def removedir(self, path, recursive=False, force=False):
        global _api_request
        if not path:
            raise PathError(path)

        path = normpath(path)

        item = self._get_item_by_path(path)
        if not item:
            raise ResourceNotFoundError(path)
        if item['type'] != _ITEM_TYPE_FOLDER:
            raise ResourceInvalidError(path)

        return _api_request(
            self,
            'DELETE',
            'folders/{}'.format(item['id']),
            params={'recursive': str(recursive).lower()}
        )


    @synchronize
    def remove(self, path):
        global _api_request
        if not path:
            raise PathError(path)

        path =normpath(path)

        item_info = self.getinfo(path)
        if item_info['is_dir']:
            raise ResourceInvalidError(path)

        _api_request(
            self,
            'DELETE',
            'files/{}'.format(item_info['id']),
            headers={'If-Match': str(item_info['sha1'])},
        )


    @synchronize
    def isfile(self, path):
        item = self._get_item_by_path(path)
        return item and item['type'] == _ITEM_TYPE_FILE


    @synchronize
    def isdir(self, path):
        item = self._get_item_by_path(path)
        return item and item['type'] == _ITEM_TYPE_FOLDER


    @synchronize
    def listdir(self,
                path="./",
                wildcard=None,
                full=False,
                absolute=False,
                dirs_only=False,
                files_only=False):
        if not path:
            raise PathError(path)

        path = normpath(path)

        item = self._get_item_by_path(path)
        if not item:
            raise ResourceNotFoundError(path)
        if item['type'] != _ITEM_TYPE_FOLDER:
            raise ResourceInvalidError(path)

        item_children = self._get_children_items(item['id'])
        result = []
        for child in item_children.values():
            child_type = child['type']
            if dirs_only and child_type != _ITEM_TYPE_FOLDER:
                continue
            if files_only and child_type != _ITEM_TYPE_FILE:
                continue

            child_path = child['name']
            if full:
                child_path = pathjoin(path, child_path)

            result.append(child_path)

        return result


    @synchronize
    def getinfo(self, path):
        global _api_request
        if not path:
            raise PathError(path)

        path = normpath(path)

        item = self._get_item_by_path(path)
        if not item:
            raise ResourceNotFoundError(path)

        is_dir = item['type'] == _ITEM_TYPE_FOLDER
        item_id = item['id']

        info = {
            'name': item['name'],
            'id': item_id,
            'is_dir': is_dir,
            }

        if is_dir:
            status_code, item_info = _api_request(
                self,
                'GET',
                'folders/{}'.format(item_id),
            )
        else:
            status_code, item_info = _api_request(
                self,
                'GET',
                'files/{}'.format(item_id),
            )

            if 'code' in item_info or 'size' not in item_info:
                if item_info['code'] == 'invalid_item':
                    raise ResourceNotFoundError

            info['sha1'] = item_info['sha1']

        info.update({
            'size': item_info['size'],
            'created_time': iso8601.parse_date(item_info['created_at']),
            'accessed_time': iso8601.parse_date(item_info['modified_at']),
            'modified_time': iso8601.parse_date(item_info['modified_at']),
            })
        return info

    @synchronize
    def exists(self, path):
        try:
            item_info = self.getinfo(path)
        except ResourceNotFoundError:
            return False

        return True

    @synchronize
    def rename(self, src, dst):
        global _api_request
        if not src:
            raise PathError(src)

        src = normpath(src)
        item = self._get_item_by_path(src)
        if not item:
            raise ResourceNotFoundError(src)

        dst = normpath(dst)
        new_name = basename(dst)

        if item['type'] == _ITEM_TYPE_FILE:
            resource_name = 'files'
        else:
            resource_name = 'folders'
        _api_request(
            self,
            'PUT',
            '{}/{}'.format(resource_name, item['id']),
            data={'name': new_name},
        )

    def _move(self, src, dst, overwrite=False):
        global _api_request
        if not src:
            raise PathError(src)

        src = normpath(src)
        item = self._get_item_by_path(src)
        if not item:
            raise ResourceNotFoundError(src)

        new_parent_box_id, name = self._get_parent_box_id_from_path(dst, recursive=False, allow_recreate=False)

        if item['type'] == _ITEM_TYPE_FILE:
            resource_name = 'files'
        else:
            resource_name = 'folders'
        _api_request(
            self,
            'PUT',
            '{}/{}'.format(resource_name, item['id']),
            data={'parent': {'id': new_parent_box_id}},
        )

    @synchronize
    def move(self, src, dst, overwrite=False):
        self._move(src, dst, overwrite)

    @synchronize
    def movedir(self, src, dst, overwrite=False, ignore_errors=False, chunk_size=16384):
        self._move(src, dst, overwrite)

    @synchronize
    def walk(self,
            path='/',
            wildcard=None,
            dir_wildcard=None,
            search="breadth",
            ignore_errors=False):
        global _api_request
        result = _api_request(
            self,
            'GET',
            'folders/{}/items'.format(self._root_id),
            params={'view':'subfolder_sync_forked_tree'}

        )
        root_node = BoxNode.root()
        root_node.add_all_children(result[1]['items'])

        if search == "depth":
            return root_node.depth_first()
        return root_node.breadth_first()

    def _copy(self, src, dst, overwrite=False):
        global _api_request
        if not src:
            raise PathError(src)

        src = normpath(src)
        item = self._get_item_by_path(src)
        if not item:
            raise ResourceNotFoundError(src)

        new_parent_box_id, name = self._get_parent_box_id_from_path(dst, recursive=False, allow_recreate=False)

        if item['type'] == _ITEM_TYPE_FILE:
            resource_name = 'files'
        else:
            resource_name = 'folders'
        _api_request(
            self,
            'POST',
            '{}/{}/copy'.format(resource_name, item['id']),
            data={'parent': {'id': new_parent_box_id}},
        )

    @synchronize
    def copy(self, src, dst, overwrite=False):
        self._copy(src, dst, overwrite)

    @synchronize
    def copydir(self, src, dst, overwrite=False, ignore_errors=False, chunk_size=16384):
        self._copy(src, dst, overwrite)


if __name__ == '__main__':
    handler = logging.StreamHandler()
    logger = logging.getLogger('fs.boxfs')
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    from fs.wrapfs.debugfs import DebugFS
    boxfs = DebugFS(BoxFS(
        auth_token='YOUR_AUTH_TOKEN'
    ))

    boxfs.makedir('test/foo/bar', recursive=True, allow_recreate=True)
    boxfs.tree()
    boxfs.removedir('test/foo/bar')
    print boxfs.getinfo('test/foo')
    boxfs.rename('test/foo', 'bar')
