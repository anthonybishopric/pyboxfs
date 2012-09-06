"""
fs.contrib.boxfs
================

PyFilesystem interface for items in Box.
"""

import json
import logging
import urlparse

import iso8601
import requests

from fs.base import (
    FS,
    synchronize,
)
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


__author__ = 'Kunal Parmar <kparmar@box.com>'


_ITEM_TYPE_FILE = 'file'
_ITEM_TYPE_FOLDER = 'folder'


class BoxFS(FS):
    """A filesystem stored in Box."""

    _box_fs_api_key = 'b3aed1e02ea1d258ca2c2f8d5e0f7c5900bb9fcb'
    _box_api_base_url = 'https://api.box.com/2.0/'


    def __init__(self,
                 auth_token,
                 api_key=_box_fs_api_key,
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
                self._auth_token,
            ),
        }

    def _is_failed_status_code(self, status_code):
        """Returns whether the status code indicates failure."""
        return (status_code < requests.codes.OK
                or status_code >= requests.codes.MULTIPLE_CHOICES)

    def _api_request(self,
                     method,
                     resource,
                     params=None,
                     data=None,
                     headers=None):
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
        url = urlparse.urljoin(self._box_api_base_url, resource)
        if data:
            data = json.dumps(data)
        if headers:
            headers = headers.copy().update(self._default_headers)
        else:
            headers = self._default_headers
        response = requests.request(
            method,
            url,
            params=params,
            data=data,
            headers=headers,
        )
        if self._is_failed_status_code(response.status_code):
            self._logger.info('%s %s failed with response %s',
                              method, url, response.content)
        return response.status_code, response.json

    def _get_children_items(self, box_id):
        """Returns the children items for an item.

        :param box_id:
            The id of the parent whose children will be returned.
        :type box_id:
            `str`

        :returns:
            A dictionary with the child name as key and child info as value.
            The child info includes data as returned by the API call.
        :rtype:
            `dict`
        """
        result = {}
        _status_code, items = self._api_request(
            'GET',
            'folders/{}/items'.format(box_id),
        )
        for item in items['entries']:
            result[item['name']] = item
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
        _status_code, item = self._api_request(
            'POST',
            'folders/{}'.format(parent_box_id),
            data={'name': name},
        )
        return item

    @synchronize
    def makedir(self, path, recursive=False, allow_recreate=False):
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
                return
            else:
                raise DestinationExistsError(path)

        self._makedir(parent_box_id, dirname)

    @synchronize
    def removedir(self, path, recursive=False, force=False):
        if not path:
            raise PathError(path)

        path = normpath(path)

        item = self._get_item_by_path(path)
        if not item:
            raise ResourceNotFoundError(path)
        if item['type'] != _ITEM_TYPE_FOLDER:
            raise ResourceInvalidError(path)

        self._api_request(
            'DELETE',
            'folders/{}'.format(item['id']),
            params={'force':force},
        )

    @synchronize
    def remove(self, path):
        if not path:
            raise PathError(path)

        path = normpath(path)

        item_info = self.getinfo(path)
        if item_info['is_dir']:
            raise ResourceInvalidError(path)

        self._api_request(
            'DELETE',
            'files/{}'.format(item_info['id']),
            headers={'If-Match': item_info['etag']},
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
            _status_code, item_info = self._api_request(
                'GET',
                'folders/{}'.format(item_id),
            )
        else:
            _status_code, item_info = self._api_request(
                'GET',
                'files/{}'.format(item_id),
            )
            info['etag'] = item_info['etag']

        info.update({
            'size': item_info['size'],
            'created_time': iso8601.parse_date(item_info['created_at']),
            'accessed_time': iso8601.parse_date(item_info['modified_at']),
            'modified_time': None,
        })
        return info

    @synchronize
    def rename(self, src, dst):
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
        self._api_request(
            'PUT',
            '{}/{}'.format(resource_name, item['id']),
            data={'name': new_name},
        )

if __name__ == '__main__':
    # pylint: disable=C0103
    # Disable invalid name warnings.
    _handler = logging.StreamHandler()
    _logger = logging.getLogger('fs.boxfs')
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)

    from fs.wrapfs.debugfs import DebugFS
    _boxfs = DebugFS(BoxFS(
        auth_token='YOUR_AUTH_TOKEN',
    ))

    _boxfs.makedir('test/foo/bar', recursive=True, allow_recreate=True)
    _boxfs.tree()
    _boxfs.removedir('test/foo/bar')
    _logger.debug('%s', _boxfs.getinfo('test/foo'))
    _boxfs.rename('test/foo', 'bar')
    # pylint: enable=C0103
